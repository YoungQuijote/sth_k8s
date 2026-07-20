#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""kubectl SQLite 接应的目标与路径解析。"""

from __future__ import annotations

import dataclasses
import json
import pathlib
import subprocess
from typing import Any, Optional

from sqlite_rescue_runtime import (
    ALLOW_ANY_SELECTOR, ALLOWED_SELECTORS, DEFAULT_CONTAINER_ROOT, DISABLE_NODE_SCOPE,
    KUBECTL_BIN, KUBECONFIG, KUBECTL_CONTEXT, MAX_SELECTOR_TARGETS, MAX_STDERR_BYTES,
    NODE_NAME, POD_MATCH_SINGLE, SELECTOR_ROOTS, CommandResult, SQLiteRescueOptions,
    SQLiteRescueRequest, ServiceError, Target, basename_match,
)

class KubectlRunner:
    def __init__(self):
        self.base = [KUBECTL_BIN]
        if KUBECONFIG:
            self.base += ["--kubeconfig", KUBECONFIG]
        if KUBECTL_CONTEXT:
            self.base += ["--context", KUBECTL_CONTEXT]

    def run(self, args: list[str], *, timeout: int, input_data: Optional[bytes] = None, check: bool = True) -> CommandResult:
        argv = [*self.base, *args]
        try:
            completed = subprocess.run(argv, input=input_data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
        except FileNotFoundError as exc:
            raise ServiceError("KUBECTL_NOT_FOUND", "kubectl executable not found", http_status=503) from exc
        except subprocess.TimeoutExpired as exc:
            raise ServiceError("KUBECTL_TIMEOUT", "kubectl command timed out", http_status=504, details={"argv": argv}) from exc
        result = CommandResult(completed.stdout, completed.stderr[-MAX_STDERR_BYTES:], completed.returncode)
        if check and result.returncode != 0:
            raise ServiceError("KUBECTL_COMMAND_FAILED", "kubectl command failed", http_status=502, details={"argv": argv, "stderr": result.stderr_text})
        return result

    def exec(self, target: Target, command: list[str], *, timeout: int, input_data: Optional[bytes] = None, check: bool = True) -> CommandResult:
        args = ["exec"]
        if input_data is not None:
            args.append("-i")
        args += ["-n", target.namespace, target.pod, "-c", target.container, "--", *command]
        return self.run(args, timeout=timeout, input_data=input_data, check=check)

    def pods(self, timeout: int) -> dict[str, Any]:
        args = ["get", "pods", "-A"]
        if not DISABLE_NODE_SCOPE:
            args += ["--field-selector", f"spec.nodeName={NODE_NAME}"]
        args += ["-o", "json"]
        result = self.run(args, timeout=timeout)
        try:
            payload = json.loads(result.stdout)
        except Exception as exc:
            raise ServiceError("KUBECTL_JSON_PARSE_FAILED", str(exc), http_status=502) from exc
        return payload


def _allowed(target: Target) -> bool:
    return ALLOW_ANY_SELECTOR or any(policy.matches(target) for policy in ALLOWED_SELECTORS)


def target_root(target: Target) -> str:
    for policy in SELECTOR_ROOTS:
        if policy.matches(target) and policy.root:
            return policy.root.rstrip("/") or "/"
    return DEFAULT_CONTAINER_ROOT.rstrip("/") or "/"


def resolve_targets(runner: KubectlRunner, req: SQLiteRescueRequest) -> list[Target]:
    items = runner.pods(req.options.command_timeout_seconds).get("items") or []
    namespaces = sorted({item.get("metadata", {}).get("namespace", "") for item in items})
    namespace_hits = [item for item in namespaces if req.selector.namespace in item]
    if len(namespace_hits) != 1:
        raise ServiceError("NAMESPACE_RESOLUTION_FAILED", "namespace selector must match exactly one namespace", http_status=404, details=namespace_hits)
    namespace = namespace_hits[0]
    pod_items = []
    for item in items:
        meta, spec = item.get("metadata") or {}, item.get("spec") or {}
        if meta.get("namespace") != namespace or meta.get("deletionTimestamp"):
            continue
        if not DISABLE_NODE_SCOPE and spec.get("nodeName") != NODE_NAME:
            continue
        if req.selector.pod in meta.get("name", ""):
            pod_items.append(item)
    if not pod_items:
        raise ServiceError("POD_NOT_FOUND", "pod selector matched nothing", http_status=404)
    if len(pod_items) > req.options.max_pods or len(pod_items) > MAX_SELECTOR_TARGETS:
        raise ServiceError("TOO_MANY_PODS_MATCHED", "pod selector matched too many pods")
    if len(pod_items) > 1 and req.options.pod_match_policy == POD_MATCH_SINGLE:
        raise ServiceError("MULTIPLE_PODS_MATCHED", "pod selector matched multiple pods")
    targets = []
    for item in sorted(pod_items, key=lambda value: value.get("metadata", {}).get("name", "")):
        meta, spec, status = item.get("metadata") or {}, item.get("spec") or {}, item.get("status") or {}
        containers = [value.get("name", "") for value in spec.get("containers") or [] if req.selector.container in value.get("name", "")]
        if len(containers) != 1:
            raise ServiceError("CONTAINER_RESOLUTION_FAILED", "container selector must match exactly one container", details=containers)
        container_id = next((value.get("containerID") for value in status.get("containerStatuses") or [] if value.get("name") == containers[0]), None)
        target = Target(namespace, meta.get("name", ""), meta.get("uid"), spec.get("nodeName"), containers[0], container_id)
        if not _allowed(target):
            raise ServiceError("SELECTOR_NOT_ALLOWED", "resolved target is not allowed", http_status=403, details=dataclasses.asdict(target))
        targets.append(target)
    return targets


_LIST_SCRIPT = r'''set -eu
DIR=$1
TYPE=$2
[ -d "$DIR" ] || exit 12
for p in "$DIR"/* "$DIR"/.[!.]* "$DIR"/..?*; do
  [ ! -L "$p" ] || continue
  if [ "$TYPE" = dir ]; then [ -d "$p" ] || continue; else [ -f "$p" ] || continue; fi
  name=${p##*/}
  mtime=$(stat -c %Y "$p" 2>/dev/null || stat -f %m "$p" 2>/dev/null || echo 0)
  size=$(stat -c %s "$p" 2>/dev/null || stat -f %z "$p" 2>/dev/null || echo 0)
  printf '%s\t%s\t%s\n' "$mtime" "$size" "$name"
done'''


def list_entries(runner: KubectlRunner, target: Target, path: str, kind: str, options: SQLiteRescueOptions) -> list[dict[str, Any]]:
    result = runner.exec(target, ["sh", "-c", _LIST_SCRIPT, "sqlite-rescue", path, kind], timeout=options.command_timeout_seconds, check=False)
    if result.returncode == 12:
        raise ServiceError("PATH_NOT_DIRECTORY", f"path is not directory: {path}", http_status=404)
    if result.returncode != 0:
        raise ServiceError("REMOTE_LIST_FAILED", "list container path failed", http_status=502, details=result.stderr_text)
    entries = []
    for line in result.stdout_text.splitlines():
        parts = line.split("\t", 2)
        if len(parts) == 3:
            try:
                entries.append({"mtime": float(parts[0]), "size": int(parts[1]), "name": parts[2]})
            except ValueError:
                pass
    return entries


def canonical_root(runner: KubectlRunner, target: Target, root: str, options: SQLiteRescueOptions) -> str:
    result = runner.exec(target, ["sh", "-c", 'set -eu; cd "$1"; pwd -P', "sqlite-rescue", root], timeout=options.command_timeout_seconds, check=False)
    if result.returncode != 0:
        raise ServiceError("CONTAINER_ROOT_NOT_FOUND", "container root cannot be resolved", http_status=404, details=result.stderr_text)
    value = result.stdout_text.strip().splitlines()[-1]
    if not value.startswith("/"):
        raise ServiceError("CONTAINER_ROOT_INVALID", "resolved root is invalid", http_status=502)
    return value.rstrip("/") or "/"


def resolve_base(runner: KubectlRunner, target: Target, root: str, req: SQLiteRescueRequest) -> str:
    current = root
    for rule in req.path_segments:
        hits = [item for item in list_entries(runner, target, current, "dir", req.options) if basename_match(item["name"], rule, req.options.regex_timeout_ms)]
        if not hits:
            raise ServiceError("PATH_SEGMENT_NOT_FOUND", f"path segment matched nothing at {current}", http_status=404)
        hits.sort(key=lambda item: (item["mtime"], item["name"]), reverse=True)
        current = current.rstrip("/") + "/" + hits[0]["name"] if current != "/" else "/" + hits[0]["name"]
        try:
            pathlib.PurePosixPath(current).relative_to(pathlib.PurePosixPath(root))
        except ValueError as exc:
            raise ServiceError("PATH_ESCAPE_DETECTED", "resolved path escaped root", http_status=403) from exc
    return current
