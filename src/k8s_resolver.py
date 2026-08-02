#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""K8s 定位与容器内路径解析"""

import dataclasses
import json
from typing import Any, Literal

from models import K8sTarget, Options, RemoteLogFile, SegmentRule, Selector, ServiceError, POD_MATCH_SINGLE
from src.utils.common_utils import q, basename_match, make_source_id, validate_basename_rule
from src.utils.ssh_utils import SSHClientWrapper, kubectl_exec_cmd


def get_pods_json(ssh: SSHClientWrapper, timeout: int) -> dict[str, Any]:
    try:
        out, _, _ = ssh.run("kubectl get pods -A -o json", timeout=timeout)
    except ServiceError as e:
        e.code = "KUBECTL_GET_PODS_FAILED"
        raise
    try:
        return json.loads(out)
    except Exception as e:
        raise ServiceError("KUBECTL_JSON_PARSE_FAILED", f"kubectl json parse failed: {e}", http_status=502) from e


def _target_from_pod_item(pod: dict[str, Any], selector: Selector) -> K8sTarget:
    meta = pod.get("metadata", {})
    spec = pod.get("spec", {})
    status = pod.get("status", {})
    containers = spec.get("containers", []) or []
    container_hits = [c.get("name", "") for c in containers if selector.container in c.get("name", "")]
    if not container_hits:
        raise ServiceError("CONTAINER_NOT_FOUND", f"container selector matched nothing in pod {meta.get('name', '')}")
    if len(container_hits) > 1:
        raise ServiceError("MULTIPLE_CONTAINERS_MATCHED", f"container selector matched multiple containers in pod {meta.get('name', '')}", details=container_hits)
    container_name = container_hits[0]
    container_id = None
    for st in status.get("containerStatuses", []) or []:
        if st.get("name") == container_name:
            container_id = st.get("containerID")
            break
    return K8sTarget(
        namespace=meta.get("namespace", ""), pod=meta.get("name", ""), pod_uid=meta.get("uid"),
        container=container_name, container_id=container_id,
    )


def resolve_k8s_targets(pods_json: dict[str, Any], selector: Selector, options: Options) -> list[K8sTarget]:
    items = pods_json.get("items") or []
    ns_names = sorted({item.get("metadata", {}).get("namespace", "") for item in items})
    ns_hits = [ns for ns in ns_names if selector.namespace in ns]
    if not ns_hits:
        raise ServiceError("NAMESPACE_NOT_FOUND", "namespace selector matched nothing")
    if len(ns_hits) > 1:
        raise ServiceError("MULTIPLE_NAMESPACES_MATCHED", "namespace selector matched multiple namespaces", details=ns_hits)
    namespace = ns_hits[0]
    pod_hits = []
    for item in items:
        meta = item.get("metadata", {})
        if meta.get("namespace") == namespace and selector.pod in meta.get("name", ""):
            pod_hits.append(item)
    if not pod_hits:
        raise ServiceError("POD_NOT_FOUND", "pod selector matched nothing")
    if len(pod_hits) > 1 and options.pod_match_policy == POD_MATCH_SINGLE:
        raise ServiceError("MULTIPLE_PODS_MATCHED", "pod selector matched multiple pods", details=[p.get("metadata", {}).get("name", "") for p in pod_hits])
    pod_hits.sort(key=lambda p: p.get("metadata", {}).get("name", ""))
    return [_target_from_pod_item(pod, selector) for pod in pod_hits]


def resolve_k8s_target(pods_json: dict[str, Any], selector: Selector) -> K8sTarget:
    options = Options(pod_match_policy="all")
    return resolve_k8s_targets(pods_json, selector, options)[0]


def list_child_entries(ssh: SSHClientWrapper, target: K8sTarget, current_dir: str, entry_type: Literal["dir", "file"], options: Options) -> list[dict[str, Any]]:
    type_test = "-d" if entry_type == "dir" else "-f"
    inner = f'''set -eu
DIR={q(current_dir)}
[ -d "$DIR" ] || exit 12
for p in "$DIR"/* "$DIR"/.[!.]* "$DIR"/..?*; do
  [ ! -L "$p" ] || continue
  [ {type_test} "$p" ] || continue
  name=${{p##*/}}
  mtime=$(stat -c %Y "$p" 2>/dev/null || stat -f %m "$p" 2>/dev/null || echo 0)
  size=$(stat -c %s "$p" 2>/dev/null || stat -f %z "$p" 2>/dev/null || echo 0)
  printf '%s\t%s\t%s\n' "$mtime" "$size" "$name"
done'''
    out, err, code = ssh.run(kubectl_exec_cmd(target, inner, options.container_user), timeout=options.remote_cmd_timeout, check=False)
    if code == 12:
        raise ServiceError("PATH_NOT_DIRECTORY", f"remote path is not directory: {current_dir}")
    if code != 0:
        if options.container_user and ("unknown flag" in err.lower() or "flag provided but not defined" in err.lower()):
            raise ServiceError("KUBECTL_USER_NOT_SUPPORTED", "kubectl exec does not support --user in this environment", http_status=502, details=err[-2000:])
        raise ServiceError("REMOTE_LIST_FAILED", "list child entries failed", http_status=502, details=err[-2000:])
    entries = []
    for line in out.splitlines():
        parts = line.split("\t", 2)
        if len(parts) != 3:
            continue
        try:
            mtime = float(parts[0])
        except ValueError:
            mtime = 0.0
        try:
            size = int(parts[1])
        except ValueError:
            size = 0
        entries.append({"name": parts[2], "mtime": mtime, "size": size})
    return entries


def resolve_base_path(ssh: SSHClientWrapper, target: K8sTarget, path_segments: list[SegmentRule], options: Options) -> str:
    current = "/"
    for idx, segment in enumerate(path_segments):
        validate_basename_rule(segment, f"path_segments[{idx}].value")
        entries = list_child_entries(ssh, target, current, "dir", options)
        hits = [e for e in entries if basename_match(e["name"], segment, options.regex_timeout_ms)]
        if not hits:
            raise ServiceError("PATH_SEGMENT_NOT_FOUND", f"path segment matched nothing at {current}", details=dataclasses.asdict(segment))
        hits.sort(key=lambda x: (x["mtime"], x["name"]), reverse=True)
        current = current.rstrip("/") + "/" + hits[0]["name"] if current != "/" else "/" + hits[0]["name"]
    return current


def list_remote_log_files(ssh: SSHClientWrapper, target: K8sTarget, base_path: str, log_file_rule: SegmentRule, options: Options) -> list[RemoteLogFile]:
    validate_basename_rule(log_file_rule, "log_file.value")
    entries = list_child_entries(ssh, target, base_path, "file", options)
    hits = [e for e in entries if basename_match(e["name"], log_file_rule, options.regex_timeout_ms)]
    if not hits:
        raise ServiceError("LOG_FILE_NOT_FOUND", f"log file rule matched nothing at {base_path}", details=dataclasses.asdict(log_file_rule))
    hits.sort(key=lambda x: (x["mtime"], x["name"]), reverse=True)
    if len(hits) > options.max_log_files:
        raise ServiceError("TOO_MANY_LOG_FILES_MATCHED", f"matched log files exceeded max_log_files={options.max_log_files}", details=[h["name"] for h in hits[:100]])
    source_id = make_source_id(target, base_path)
    max_size = options.max_single_file_size_mb * 1024 * 1024
    files = []
    skipped = []
    for h in hits:
        if h["size"] > max_size:
            skipped.append({"name": h["name"], "size": h["size"], "pod": target.pod})
            continue
        files.append(RemoteLogFile(
            remote_path=base_path.rstrip("/") + "/" + h["name"], base_path=base_path, name=h["name"],
            mtime=h["mtime"], size=h["size"], source_id=source_id, namespace=target.namespace,
            pod=target.pod, pod_uid=target.pod_uid, container=target.container, container_id=target.container_id,
        ))
    if not files:
        raise ServiceError("ALL_LOG_FILES_TOO_LARGE", "all matched log files exceeded max_single_file_size_mb", details=skipped)
    return files


def stat_remote_log_files(ssh: SSHClientWrapper, target: K8sTarget, base_path: str, remote_files: list[RemoteLogFile], options: Options) -> list[RemoteLogFile]:
    if not remote_files:
        return []
    args = " ".join(q(f.name) for f in remote_files)
    inner = f'''set -eu
DIR={q(base_path)}
cd "$DIR"
for name in {args}; do
  [ -f "$name" ] || continue
  mtime=$(stat -c %Y "$name" 2>/dev/null || stat -f %m "$name" 2>/dev/null || echo 0)
  size=$(stat -c %s "$name" 2>/dev/null || stat -f %z "$name" 2>/dev/null || echo 0)
  printf '%s\t%s\t%s\n' "$mtime" "$size" "$name"
done'''
    out, _, _ = ssh.run(kubectl_exec_cmd(target, inner, options.container_user), timeout=options.remote_cmd_timeout)
    by_name = {f.name: f for f in remote_files}
    result = []
    for line in out.splitlines():
        parts = line.split("\t", 2)
        if len(parts) != 3 or parts[2] not in by_name:
            continue
        src = by_name[parts[2]]
        result.append(RemoteLogFile(
            remote_path=src.remote_path, base_path=src.base_path, name=parts[2], mtime=float(parts[0]), size=int(parts[1]),
            source_id=src.source_id, namespace=src.namespace, pod=src.pod, pod_uid=src.pod_uid,
            container=src.container, container_id=src.container_id,
        ))
    return result
