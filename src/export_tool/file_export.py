#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Kubernetes 容器文件导出编排。"""

from __future__ import annotations

import dataclasses
import os
import pathlib
import posixpath
import shutil
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any

from src.utils.common_utils import compile_pattern, make_source_id, q, regex_search, sha256_text, stable_json, validate_basename_rule
from file_export_models import OVERWRITE_REJECT, OVERWRITE_REPLACE, FileExportRequest
from file_transfer import transfer_resolved_batch
from src.k8s_resolver import get_pods_json, list_child_entries, resolve_k8s_targets
from src.models import (
    MODE_CONTAINS,
    MODE_EXACT,
    MODE_REGEX,
    K8sTarget,
    RemoteLogFile,
    ResolvedLogBatch,
    SegmentRule,
    ServiceError,
    WarningItem,
)
from src.utils.ssh_utils import SSHClientWrapper, kubectl_exec_cmd

_EXPORT_LOCKS: dict[str, threading.Lock] = {}
_EXPORT_LOCKS_GUARD = threading.Lock()
MAX_EXPORT_PREVIEW_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True)
class ExportPlan:
    target: K8sTarget
    source_dir: str
    files: list[RemoteLogFile]
    pod_key: str


def build_export_identity(target: K8sTarget) -> str:
    """仅使用真实解析出的 K8s 身份，不使用调用方 selector。"""
    payload = {
        "namespace": target.namespace,
        "pod_uid": target.pod_uid or target.pod,
        "container_id": target.container_id or target.container,
        "container": target.container,
    }
    return sha256_text(stable_json(payload))[:16]


def _destination_lock(path: pathlib.Path) -> threading.Lock:
    key = str(path.resolve(strict=False))
    with _EXPORT_LOCKS_GUARD:
        lock = _EXPORT_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _EXPORT_LOCKS[key] = lock
        return lock


def _resolve_destination(req: FileExportRequest) -> pathlib.Path:
    root = pathlib.Path(req.storage_root).expanduser().resolve(strict=False)
    candidate = (root / pathlib.PurePosixPath(req.relative_dir)).resolve(strict=False)
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ServiceError("INVALID_REQUEST", "destination.relative_dir escapes storage root") from exc
    return candidate


def _match_names(entries: list[dict[str, Any]], rule: SegmentRule, timeout_ms: int) -> list[dict[str, Any]]:
    validate_basename_rule(rule, "file export basename rule")
    if rule.mode == MODE_EXACT:
        return [entry for entry in entries if entry["name"] == rule.value]
    if rule.mode == MODE_CONTAINS:
        return [entry for entry in entries if rule.value in entry["name"]]
    if rule.mode == MODE_REGEX:
        compiled = compile_pattern(rule.value, field_name="file export basename regex")
        return [entry for entry in entries if regex_search(compiled, entry["name"], timeout_ms) is not None]
    raise ServiceError("INVALID_REQUEST", f"unsupported match mode: {rule.mode}")


def _resolve_source_dir(ssh: SSHClientWrapper, target: K8sTarget, req: FileExportRequest) -> str:
    current = req.source_root
    for idx, segment in enumerate(req.mixed_dir_segments):
        entries = list_child_entries(ssh, target, current, "dir", req.options)
        hits = _match_names(entries, segment, req.options.regex_timeout_ms)
        if not hits:
            raise ServiceError(
                "EXPORT_PATH_SEGMENT_NOT_FOUND",
                f"source.mixed_dir_segments[{idx}] matched nothing at {current}",
                details=dataclasses.asdict(segment),
            )
        if len(hits) > 1:
            hits.sort(key=lambda item: (item["mtime"], item["name"]), reverse=True)
            raise ServiceError(
                "MULTIPLE_EXPORT_PATH_SEGMENTS_MATCHED",
                f"source.mixed_dir_segments[{idx}] matched multiple directories at {current}",
                details=[item["name"] for item in hits[:100]],
            )
        current = posixpath.join(current.rstrip("/") or "/", hits[0]["name"])
    return current


def _list_export_files(
    ssh: SSHClientWrapper,
    target: K8sTarget,
    source_dir: str,
    req: FileExportRequest,
) -> list[RemoteLogFile]:
    entries = list_child_entries(ssh, target, source_dir, "file", req.options)
    by_name: dict[str, dict[str, Any]] = {}
    for rule in req.file_rules:
        for entry in _match_names(entries, rule, req.options.regex_timeout_ms):
            by_name[entry["name"]] = entry
    if not by_name:
        raise ServiceError(
            "EXPORT_FILE_NOT_FOUND",
            f"source.files matched nothing at {source_dir}",
            details=[dataclasses.asdict(rule) for rule in req.file_rules],
        )

    hits = sorted(by_name.values(), key=lambda item: (item["mtime"], item["name"]), reverse=True)
    max_single = req.options.max_single_file_size_mb * 1024 * 1024
    oversized = [entry for entry in hits if entry["size"] > max_single]
    if oversized:
        raise ServiceError(
            "EXPORT_FILE_TOO_LARGE",
            "one or more export files exceeded max_single_file_size_mb",
            details=oversized[:100],
        )

    source_id = make_source_id(target, source_dir)
    return [
        RemoteLogFile(
            remote_path=posixpath.join(source_dir, entry["name"]),
            base_path=source_dir,
            name=entry["name"],
            mtime=entry["mtime"],
            size=entry["size"],
            source_id=source_id,
            namespace=target.namespace,
            pod=target.pod,
            pod_uid=target.pod_uid,
            container=target.container,
            container_id=target.container_id,
        )
        for entry in hits
    ]


def _stat_export_files(
    ssh: SSHClientWrapper,
    plan: ExportPlan,
    req: FileExportRequest,
) -> list[RemoteLogFile]:
    names = " ".join(q(remote_file.name) for remote_file in plan.files)
    inner = f'''set -eu
DIR={q(plan.source_dir)}
cd "$DIR"
for name in {names}; do
  [ ! -L "$name" ] || continue
  [ -f "$name" ] || continue
  mtime=$(stat -c %Y "$name" 2>/dev/null || stat -f %m "$name" 2>/dev/null || echo 0)
  size=$(stat -c %s "$name" 2>/dev/null || stat -f %z "$name" 2>/dev/null || echo 0)
  printf '%s\t%s\t%s\n' "$mtime" "$size" "$name"
done'''
    out, _, _ = ssh.run(
        kubectl_exec_cmd(plan.target, inner, req.options.container_user),
        timeout=req.options.remote_cmd_timeout,
    )
    original = {remote_file.name: remote_file for remote_file in plan.files}
    result: list[RemoteLogFile] = []
    for line in out.splitlines():
        parts = line.split("\t", 2)
        if len(parts) != 3 or parts[2] not in original:
            continue
        try:
            mtime = float(parts[0])
            size = int(parts[1])
        except ValueError as exc:
            raise ServiceError("REMOTE_STAT_PARSE_FAILED", f"invalid stat output: {line}", http_status=502) from exc
        src = original[parts[2]]
        result.append(dataclasses.replace(src, mtime=mtime, size=size))
    return result


def _validate_transfer(plan: ExportPlan, post_files: list[RemoteLogFile], local_dir: pathlib.Path) -> None:
    before = {item.name: item for item in plan.files}
    after = {item.name: item for item in post_files}
    if set(before) != set(after):
        raise ServiceError(
            "EXPORT_REMOTE_FILE_SET_CHANGED",
            "remote file set changed during export",
            http_status=409,
            details={"before": sorted(before), "after": sorted(after)},
        )

    changed = []
    for name, old in before.items():
        new = after[name]
        if old.mtime != new.mtime or old.size != new.size:
            changed.append({
                "name": name,
                "before_mtime": old.mtime,
                "after_mtime": new.mtime,
                "before_size": old.size,
                "after_size": new.size,
            })
    if changed:
        raise ServiceError(
            "EXPORT_REMOTE_FILE_CHANGED",
            "remote file changed during export",
            http_status=409,
            details=changed,
        )

    actual_names = {path.name for path in local_dir.iterdir() if path.is_file()}
    if actual_names != set(after):
        raise ServiceError(
            "EXPORT_LOCAL_FILE_SET_MISMATCH",
            "local exported files do not match remote file set",
            http_status=502,
            details={"expected": sorted(after), "actual": sorted(actual_names)},
        )
    size_mismatches = []
    for name, remote_file in after.items():
        local_size = (local_dir / name).stat().st_size
        if local_size != remote_file.size:
            size_mismatches.append({"name": name, "remote_size": remote_file.size, "local_size": local_size})
    if size_mismatches:
        raise ServiceError(
            "EXPORT_LOCAL_FILE_SIZE_MISMATCH",
            "one or more exported files have unexpected local size",
            http_status=502,
            details=size_mismatches,
        )


def _remove_path(path: pathlib.Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink(missing_ok=True)


def _commit_staging(staging: pathlib.Path, destination: pathlib.Path, overwrite_policy: str) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not destination.exists():
        os.replace(staging, destination)
        return
    if overwrite_policy == OVERWRITE_REJECT:
        raise ServiceError("EXPORT_TARGET_EXISTS", f"export target already exists: {destination}", http_status=409)
    if overwrite_policy != OVERWRITE_REPLACE:
        raise ServiceError("INVALID_REQUEST", f"unsupported overwrite_policy: {overwrite_policy}")

    backup = destination.with_name(destination.name + f".old-{os.getpid()}-{time.time_ns()}")
    os.replace(destination, backup)
    try:
        os.replace(staging, destination)
    except BaseException:
        os.replace(backup, destination)
        raise
    else:
        _remove_path(backup)


def _build_plans(ssh: SSHClientWrapper, req: FileExportRequest) -> list[ExportPlan]:
    targets = resolve_k8s_targets(
        get_pods_json(ssh, req.options.remote_cmd_timeout),
        req.selector,
        req.options,
    )
    if len(targets) > req.options.max_pods:
        raise ServiceError(
            "TOO_MANY_EXPORT_PODS",
            f"matched pods exceeded max_pods={req.options.max_pods}",
            details=[target.pod for target in targets[:100]],
        )

    plans: list[ExportPlan] = []
    seen_keys: set[str] = set()
    total_files = 0
    total_size = 0
    total_preview_size = 0
    max_total_size = req.options.max_total_size_mb * 1024 * 1024
    for target in targets:
        source_dir = _resolve_source_dir(ssh, target, req)
        files = _list_export_files(ssh, target, source_dir, req)
        pod_key = build_export_identity(target)
        if pod_key in seen_keys:
            raise ServiceError("EXPORT_IDENTITY_COLLISION", f"duplicate export identity for pod {target.pod}")
        seen_keys.add(pod_key)
        total_files += len(files)
        total_size += sum(remote_file.size for remote_file in files)
        if total_files > req.options.max_files:
            raise ServiceError(
                "TOO_MANY_EXPORT_FILES",
                f"matched files exceeded max_files={req.options.max_files}",
                details={"total_files": total_files},
            )
        if req.options.show_details:
            total_preview_size += sum(min(remote_file.size, req.options.show_limit) for remote_file in files)
            if total_preview_size > MAX_EXPORT_PREVIEW_BYTES:
                raise ServiceError(
                    "EXPORT_PREVIEW_SIZE_EXCEEDED",
                    "content preview exceeded service response budget",
                    details={"preview_bytes": total_preview_size, "limit_bytes": MAX_EXPORT_PREVIEW_BYTES},
                )
        if total_size > max_total_size:
            raise ServiceError(
                "EXPORT_TOTAL_SIZE_EXCEEDED",
                f"matched files exceeded max_total_size_mb={req.options.max_total_size_mb}",
                details={"total_size_bytes": total_size, "limit_bytes": max_total_size},
            )
        plans.append(ExportPlan(target=target, source_dir=source_dir, files=files, pod_key=pod_key))
    return plans


def _transfer_with_retry(
    ssh: SSHClientWrapper,
    plan: ExportPlan,
    local_dir: pathlib.Path,
    req: FileExportRequest,
    warnings: list[WarningItem],
) -> None:
    attempts = req.options.copy_retry + 1
    last_error: Exception | None = None
    for attempt in range(attempts):
        shutil.rmtree(local_dir, ignore_errors=True)
        local_dir.mkdir(parents=True, exist_ok=True)
        try:
            transfer_resolved_batch(
                ssh,
                ResolvedLogBatch(target=plan.target, base_path=plan.source_dir, remote_files=plan.files),
                local_dir,
                req.options,
                warnings,
            )
            return
        except Exception as exc:
            last_error = exc
            if attempt + 1 >= attempts:
                raise
    assert last_error is not None
    raise last_error


def _build_file_items(
    plans: list[ExportPlan],
    destination: pathlib.Path,
    req: FileExportRequest,
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for plan in plans:
        for remote_file in plan.files:
            local_path = destination / plan.pod_key / remote_file.name
            item: dict[str, Any] = {
                "name": remote_file.name,
                "namespace": plan.target.namespace,
                "pod": plan.target.pod,
                "pod_uid": plan.target.pod_uid,
                "container": plan.target.container,
                "container_id": plan.target.container_id,
                "pod_key": plan.pod_key,
                "source_dir": plan.source_dir,
                "remote_path": remote_file.remote_path,
                "relative_path": f"{plan.pod_key}/{remote_file.name}",
                "local_path": str(local_path),
                "size": remote_file.size,
                "mtime": remote_file.mtime,
            }
            if req.options.show_details:
                with local_path.open("rb") as stream:
                    item["content"] = stream.read(req.options.show_limit).decode(
                        req.options.show_decode,
                        errors="replace",
                    )
            items.append(item)
    return items


def handle_file_export(req: FileExportRequest) -> dict[str, Any]:
    destination = _resolve_destination(req)
    export_id = uuid.uuid4().hex
    staging = destination.with_name(destination.name + f".part-{os.getpid()}-{threading.get_ident()}-{time.time_ns()}")
    warnings: list[WarningItem] = []

    with _destination_lock(destination):
        if destination.exists() and req.overwrite_policy == OVERWRITE_REJECT:
            raise ServiceError("EXPORT_TARGET_EXISTS", f"export target already exists: {destination}", http_status=409)
        shutil.rmtree(staging, ignore_errors=True)
        staging.mkdir(parents=True, exist_ok=False)
        try:
            with SSHClientWrapper(req.ssh) as ssh:
                plans = _build_plans(ssh, req)
                for plan in plans:
                    local_dir = staging / plan.pod_key
                    _transfer_with_retry(ssh, plan, local_dir, req, warnings)
                    post_files = _stat_export_files(ssh, plan, req)
                    _validate_transfer(plan, post_files, local_dir)
            _commit_staging(staging, destination, req.overwrite_policy)
            files = _build_file_items(plans, destination, req)
        except Exception:
            shutil.rmtree(staging, ignore_errors=True)
            raise

        return {
            "success": True,
            "export_id": export_id,
            "destination": {
                "storage_root": req.storage_root,
                "relative_dir": req.relative_dir,
                "path": str(destination),
                "overwrite_policy": req.overwrite_policy,
            },
            "files": files,
            "meta": {
                "trace": req.trace,
                "source_root_key": req.source_root_key,
                "source_root_custom": req.source_root_custom,
                "storage_root_custom": req.storage_root_custom,
                "pod_count": len(plans),
                "file_count": len(files),
                "total_size": sum(item["size"] for item in files),
                "transfer_mode": req.options.transfer_mode,
            },
            "warnings": [warning.as_dict() for warning in warnings],
            "error": None,
        }
