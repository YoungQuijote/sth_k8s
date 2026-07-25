#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ZIP/GZIP 安全解压与扫描"""

import contextlib
import json
import os
import pathlib
import shutil
import threading
import time
import zipfile
from dataclasses import dataclass
from typing import Any, Optional

from loguru import logger
from models import ExtractRequest, LocalLogFile, K8sTarget, RemoteLogFile, ResolvedLogBatch, ServiceError, Options, WarningItem
from models import RETURN_MODE_FULL_LINE, RETURN_MODE_MATCH, RETURN_MODE_VALUE
from common_utils import atomic_write_json, compile_pattern, dir_size_bytes, extract_match_text, get_zip_cache_lock, make_source_id, now_ts, q, regex_search, reverse_read_lines, sha256_text, stable_json
from log_fetcher import is_zip_log_file
from gzip_utils import get_cached_gzip_extract, is_gzip_log_file, is_gzip_path, read_remote_gzip_tail_text
from ssh_utils import SSHClientWrapper, kubectl_exec_cmd
from preset_scripts import REAL_TIME_ZIP_TAIL_SCRIPT
from regex_rule import FIELD_RULES


def safe_extract_zip(zip_path: pathlib.Path, dest_dir: pathlib.Path, options: Options, warnings: list[WarningItem]) -> list[pathlib.Path]:
    extracted: list[pathlib.Path] = []
    max_total = options.max_zip_uncompressed_size_mb * 1024 * 1024
    total = 0
    try:
        with zipfile.ZipFile(zip_path) as zf:
            infos = zf.infolist()
            if len(infos) > options.max_zip_entries:
                warnings.append(WarningItem("ZIP_TOO_MANY_ENTRIES", "zip entries exceeded limit, skip zip", file=str(zip_path)))
                return []
            for info in infos:
                if info.is_dir():
                    continue
                name = info.filename
                if name.startswith("/") or ".." in pathlib.PurePosixPath(name).parts:
                    warnings.append(WarningItem("ZIP_UNSAFE_ENTRY", "unsafe zip entry, skip zip", file=str(zip_path), details=name))
                    return []
                total += int(info.file_size)
                if total > max_total:
                    warnings.append(WarningItem("ZIP_TOO_LARGE", "zip uncompressed size exceeded limit, skip zip", file=str(zip_path)))
                    return []
            dest_dir.mkdir(parents=True, exist_ok=True)
            for info in infos:
                if info.is_dir():
                    continue
                target = (dest_dir / info.filename).resolve()
                if not str(target).startswith(str(dest_dir.resolve())):
                    warnings.append(WarningItem("ZIP_UNSAFE_ENTRY", "unsafe zip entry, skip zip", file=str(zip_path), details=info.filename))
                    return []
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info, "r") as src, target.open("wb") as dst:
                    shutil.copyfileobj(src, dst, length=1024 * 1024)
                extracted.append(target)
    except Exception as e:
        warnings.append(WarningItem("ZIP_DECOMPRESS_FAILED", f"zip decompress failed: {e}", file=str(zip_path)))
        return []
    return extracted


def cache_entry_dir_for_local_file(path: pathlib.Path) -> pathlib.Path:
    resolved = path.resolve()
    for parent in resolved.parents:
        if parent.name == "files":
            return parent.parent
    return resolved.parent


def zip_fingerprint(zip_path: pathlib.Path) -> str:
    st = zip_path.stat()
    return sha256_text(stable_json({"path": str(zip_path.resolve()), "size": st.st_size, "mtime_ns": st.st_mtime_ns}))


def list_regular_files(root: pathlib.Path) -> list[pathlib.Path]:
    if not root.exists():
        return []
    result = [p for p in root.rglob("*") if p.is_file() and p.name != ".meta.json"]
    result.sort(key=lambda x: str(x), reverse=True)
    return result


def update_zip_cache_meta(extract_dir: pathlib.Path, zip_path: pathlib.Path) -> None:
    meta_path = extract_dir / ".meta.json"
    meta = {"zip_path": str(zip_path.resolve()), "last_used_at": now_ts(), "updated_at": now_ts()}
    if meta_path.exists():
        with contextlib.suppress(Exception):
            with meta_path.open("r", encoding="utf-8") as f:
                old = json.load(f)
            meta["created_at"] = old.get("created_at") or old.get("updated_at") or now_ts()
    meta.setdefault("created_at", now_ts())
    try:
        atomic_write_json(meta_path, meta)
    except FileNotFoundError:
        return


def try_update_zip_cache_meta(extract_dir: pathlib.Path, zip_path: pathlib.Path, warnings: list[WarningItem]) -> None:
    try:
        update_zip_cache_meta(extract_dir, zip_path)
    except FileNotFoundError as e:
        warnings.append(WarningItem("ZIP_CACHE_META_UPDATE_RACE", "zip cache meta update skipped because concurrent request changed temp file", file=str(zip_path), details=str(e)))
    except Exception as e:
        warnings.append(WarningItem("ZIP_CACHE_META_UPDATE_FAILED", f"zip cache metadata update failed: {e}", file=str(zip_path)))


def read_zip_cache_last_used(extract_dir: pathlib.Path) -> float:
    meta_path = extract_dir / ".meta.json"
    if not meta_path.exists():
        return 0.0
    try:
        with meta_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return float(data.get("last_used_at") or 0.0)
    except Exception:
        return 0.0


def gc_zip_extract_cache(root: pathlib.Path, options: Options, warnings: list[WarningItem]) -> None:
    if not root.exists():
        return
    try:
        now = now_ts()
        ttl = max(0, options.zip_extract_cache_ttl_seconds)
        dirs = [p for p in root.iterdir() if p.is_dir() and ".part-" not in p.name]
        for d in dirs:
            last_used = read_zip_cache_last_used(d)
            if ttl and last_used and now - last_used > ttl:
                shutil.rmtree(d, ignore_errors=True)
        max_size = options.zip_extract_cache_max_size_mb * 1024 * 1024
        total = dir_size_bytes(root)
        if max_size > 0 and total > max_size:
            dirs = [p for p in root.iterdir() if p.is_dir() and ".part-" not in p.name]
            dirs.sort(key=read_zip_cache_last_used)
            for d in dirs:
                if total <= max_size:
                    break
                size = dir_size_bytes(d)
                shutil.rmtree(d, ignore_errors=True)
                total -= size
    except Exception as e:
        warnings.append(WarningItem("ZIP_CACHE_GC_FAILED", f"zip extract cache gc failed: {e}"))


def get_cached_zip_extract(zip_path: pathlib.Path, options: Options, warnings: list[WarningItem]) -> list[pathlib.Path]:
    entry_dir = cache_entry_dir_for_local_file(zip_path)
    root = entry_dir / "zip_extract"
    root.mkdir(parents=True, exist_ok=True)
    gc_zip_extract_cache(root, options, warnings)
    fingerprint = zip_fingerprint(zip_path)
    with get_zip_cache_lock(fingerprint):
        extract_dir = root / fingerprint
        meta_path = extract_dir / ".meta.json"
        if extract_dir.is_dir() and meta_path.is_file():
            try_update_zip_cache_meta(extract_dir, zip_path, warnings)
            return list_regular_files(extract_dir)
        staging = root / f"{fingerprint}.part-{os.getpid()}-{threading.get_ident()}-{time.time_ns()}"
        shutil.rmtree(staging, ignore_errors=True)
        staging.mkdir(parents=True, exist_ok=True)
        extracted = safe_extract_zip(zip_path, staging, options, warnings)
        if not extracted:
            shutil.rmtree(staging, ignore_errors=True)
            return []
        try_update_zip_cache_meta(staging, zip_path, warnings)
        if extract_dir.exists():
            shutil.rmtree(extract_dir, ignore_errors=True)
        os.replace(staging, extract_dir)
        return list_regular_files(extract_dir)


@dataclass
class ScanState:
    results: dict[str, list[str]]
    conversation_ids: dict[str, Optional[str]]
    missed: set[str]


def build_default_coarse_regex(req: ExtractRequest) -> str:
    logger.info(f"Fetching _field={req.field}")
    return FIELD_RULES.get(req.field) or r"Chat\[(?P<chat_id>[^\]]+)\]"


def scan_line(line: str, chat_id_set: set[str], coarse_pattern: Any, data_pattern: Optional[Any], state: ScanState, max_matches_per_chat_id: int, timeout_ms: int, return_mode: str = RETURN_MODE_VALUE) -> None:
    coarse_match = regex_search(coarse_pattern, line, timeout_ms)
    if not coarse_match:
        return
    groupdict = coarse_match.groupdict() if hasattr(coarse_match, "groupdict") else {}
    chat_id = groupdict.get("chat_id")
    if not chat_id or chat_id not in chat_id_set or len(state.results[chat_id]) >= max_matches_per_chat_id:
        return
    data_match = regex_search(data_pattern, line, timeout_ms) if data_pattern is not None else None
    if data_pattern is not None and not data_match:
        return
    if return_mode == RETURN_MODE_FULL_LINE:
        value = line
    elif return_mode == RETURN_MODE_MATCH:
        value = data_match.group(0) if data_match is not None else coarse_match.group(0)
    elif data_match is not None:
        value = extract_match_text(data_match)
    else:
        value = groupdict.get("value") or coarse_match.group(0)
    state.results[chat_id].append(value)
    state.conversation_ids[chat_id] = groupdict.get("conversation_id") or state.conversation_ids.get(chat_id)
    if len(state.results[chat_id]) >= max_matches_per_chat_id:
        state.missed.discard(chat_id)


def all_reached_limit(state: ScanState, max_matches_per_chat_id: int) -> bool:
    return all(len(v) >= max_matches_per_chat_id for v in state.results.values())


def scan_regular_file(path: pathlib.Path, chat_id_set: set[str], coarse_pattern: Any, data_pattern: Optional[Any], state: ScanState, options: Options, return_mode: str) -> None:
    for line in reverse_read_lines(path):
        scan_line(line, chat_id_set, coarse_pattern, data_pattern, state, options.max_matches_per_chat_id, options.regex_timeout_ms, return_mode)
        if all_reached_limit(state, options.max_matches_per_chat_id):
            break


def scan_text_reversed(text: str, chat_id_set: set[str], coarse_pattern: Any, data_pattern: Optional[Any], state: ScanState, options: Options, return_mode: str) -> None:
    for line in reversed(text.splitlines()):
        scan_line(line, chat_id_set, coarse_pattern, data_pattern, state, options.max_matches_per_chat_id, options.regex_timeout_ms, return_mode)
        if all_reached_limit(state, options.max_matches_per_chat_id):
            break


def read_remote_plain_tail_text(ssh: SSHClientWrapper, target: K8sTarget, file: RemoteLogFile, options: Options) -> str:
    cmd = kubectl_exec_cmd(target, f"tail -c {int(options.real_tail_bytes)} -- {q(file.remote_path)}", options.container_user)
    out, err, code = ssh.run(cmd, timeout=options.remote_cmd_timeout, check=False)
    if code != 0:
        raise ServiceError("REAL_TIME_TAIL_FAILED", f"real_time tail failed for pod {target.pod}", http_status=502, details={"cmd": cmd, "stderr": err[-4000:], "remote_path": file.remote_path})
    return out


def read_remote_zip_tail_text(ssh: SSHClientWrapper, target: K8sTarget, file: RemoteLogFile, options: Options) -> str:
    max_total = options.max_zip_uncompressed_size_mb * 1024 * 1024
    inner = f"python3 -c {q(REAL_TIME_ZIP_TAIL_SCRIPT)} {q(file.remote_path)} {int(options.real_tail_bytes)} {int(options.max_zip_entries)} {int(max_total)}"
    cmd = kubectl_exec_cmd(target, inner, options.container_user)
    out, err, code = ssh.run(cmd, timeout=options.remote_cmd_timeout, check=False)
    if code != 0:
        if "python3: not found" in err.lower() or "python: not found" in err.lower():
            raise ServiceError("REAL_TIME_ZIP_READER_NOT_AVAILABLE", "python3 is not available in container, cannot inspect zip in real_time mode", http_status=502, details=err[-4000:])
        raise ServiceError("REAL_TIME_ZIP_TAIL_FAILED", f"real_time zip tail failed for pod {target.pod}", http_status=502, details=err[-4000:])
    return out


def read_remote_real_time_text(ssh: SSHClientWrapper, target: K8sTarget, file: RemoteLogFile, options: Options) -> str:
    if is_zip_log_file(file):
        return read_remote_zip_tail_text(ssh, target, file, options)
    if is_gzip_log_file(file):
        return read_remote_gzip_tail_text(ssh, target, file, options)
    return read_remote_plain_tail_text(ssh, target, file, options)


def _make_scan_result(req: ExtractRequest, state: ScanState, scanned_files: int) -> dict[str, Any]:
    return {
        "items": [{"chat_id": chat_id, "conversation_id": state.conversation_ids.get(chat_id), "matches": values, "matched_count": len(values)} for chat_id, values in state.results.items()],
        "missed_chat_ids": [chat_id for chat_id, values in state.results.items() if not values],
        "scanned_files": scanned_files,
    }


def scan_logs(req: ExtractRequest, local_files: list[LocalLogFile], warnings: list[WarningItem]) -> dict[str, Any]:
    chat_id_set = set(req.chat_ids)
    state = ScanState({chat_id: [] for chat_id in req.chat_ids}, {chat_id: None for chat_id in req.chat_ids}, set(req.chat_ids))
    coarse_pattern = compile_pattern(req.coarse_regex or build_default_coarse_regex(req), field_name="coarse_regex")
    data_pattern = compile_pattern(req.data_regex, field_name="data_regex") if req.data_regex else None
    scanned_files = 0
    for item in local_files:
        path = pathlib.Path(item.local_path)
        if not path.is_file():
            continue
        scanned_files += 1
        if zipfile.is_zipfile(path):
            scan_files = get_cached_zip_extract(path, req.options, warnings)
        elif is_gzip_path(path):
            scan_files = get_cached_gzip_extract(path, req.options, warnings)
        else:
            scan_files = [path]
        for scan_file in scan_files:
            if scan_file.is_file():
                scan_regular_file(scan_file, chat_id_set, coarse_pattern, data_pattern, state, req.options, req.return_mode)
            if all_reached_limit(state, req.options.max_matches_per_chat_id):
                break
        if all_reached_limit(state, req.options.max_matches_per_chat_id):
            break
    return _make_scan_result(req, state, scanned_files)


def scan_remote_logs_real_time(ssh: SSHClientWrapper, req: ExtractRequest, batches: list[ResolvedLogBatch], warnings: list[WarningItem]) -> tuple[dict[str, Any], dict[str, Any]]:
    chat_id_set = set(req.chat_ids)
    state = ScanState({chat_id: [] for chat_id in req.chat_ids}, {chat_id: None for chat_id in req.chat_ids}, set(req.chat_ids))
    coarse_pattern = compile_pattern(req.coarse_regex or build_default_coarse_regex(req), field_name="coarse_regex")
    data_pattern = compile_pattern(req.data_regex, field_name="data_regex") if req.data_regex else None
    scanned_files = 0
    failed_files = []
    resolved_sources = []
    log_files = []
    for batch in batches:
        source_id = batch.remote_files[0].source_id if batch.remote_files else make_source_id(batch.target, batch.base_path)
        resolved_sources.append({"source_id": source_id, "namespace": batch.target.namespace, "pod": batch.target.pod, "pod_uid": batch.target.pod_uid, "container": batch.target.container, "container_id": batch.target.container_id, "base_path": batch.base_path})
        for file in batch.remote_files:
            try:
                text = read_remote_real_time_text(ssh, batch.target, file, req.options)
            except ServiceError as e:
                detail = {"pod": batch.target.pod, "container": batch.target.container, "remote_path": file.remote_path, "code": e.code, "message": e.message, "details": e.details}
                failed_files.append(detail)
                warnings.append(WarningItem("REAL_TIME_FILE_READ_FAILED", f"real_time read failed; skip file {file.name}", file=file.remote_path, details=detail))
                continue
            scanned_files += 1
            log_files.append({"source_id": file.source_id, "pod": file.pod, "container": file.container, "remote_path": file.remote_path, "local_path": None, "mtime": file.mtime, "size": file.size})
            scan_text_reversed(text, chat_id_set, coarse_pattern, data_pattern, state, req.options, req.return_mode)
            if all_reached_limit(state, req.options.max_matches_per_chat_id):
                break
        if all_reached_limit(state, req.options.max_matches_per_chat_id):
            break
    if scanned_files <= 0 and failed_files:
        raise ServiceError("REAL_TIME_ALL_FILES_FAILED", "all real_time log files failed to read", http_status=502, details=failed_files)
    scan_result = _make_scan_result(req, state, scanned_files)
    pseudo_entry = {
        "cache_key": None, "created_at": now_ts(), "updated_at": now_ts(), "last_used_at": now_ts(),
        "transfer_mode": "real_time", "resolved": resolved_sources[0] if resolved_sources else {},
        "resolved_sources": resolved_sources, "files": log_files,
    }
    return scan_result, pseudo_entry
