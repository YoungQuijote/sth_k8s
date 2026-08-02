#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""请求解析与日志获取主编排。"""

import pathlib
from typing import Any, Optional

import paramiko

from models import (
    DEFAULT_REAL_TAIL_BYTES, MAX_REAL_TAIL_BYTES, MODE_CONTAINS, MODE_EXACT, MODE_REGEX,
    POD_MATCH_ALL, POD_MATCH_SINGLE, RETURN_MODE_FULL_LINE, RETURN_MODE_MATCH, RETURN_MODE_VALUE,
    TRANSFER_COMPATIBLE, TRANSFER_STREAM, ExtractRequest, Options, ResolvedLogBatch, SegmentRule,
    Selector, ServiceError, SSHInfo, WarningItem,
)
from src.utils.common_utils import make_source_id, now_ts, parse_bool
from src.utils.cache_utils import (
    CACHE, build_cache_key, cache_entry_fingerprint, cache_files_exist, cache_last_refresh_ts,
    cache_refresh_interval_remaining, cached_signature, entry_to_local_files, remote_batches_signature,
    should_skip_refresh_by_interval,
)
from src.utils.ssh_utils import SSHClientWrapper
from k8s_resolver import get_pods_json, list_remote_log_files, resolve_base_path, resolve_k8s_targets, stat_remote_log_files
from log_fetcher import fetch_logs
from src.utils.read_utils import scan_logs, scan_remote_logs_real_time

def parse_segment(obj: Any, field_name: str) -> SegmentRule:
    if not isinstance(obj, dict):
        raise ServiceError("INVALID_REQUEST", f"{field_name} must be object")
    mode = obj.get("mode")
    value = obj.get("value")
    if mode not in (MODE_EXACT, MODE_CONTAINS, MODE_REGEX):
        raise ServiceError("INVALID_REQUEST", f"{field_name}.mode must be exact, contains or regex")
    if not isinstance(value, str) or not value:
        raise ServiceError("INVALID_REQUEST", f"{field_name}.value must be non-empty string")
    return SegmentRule(mode=mode, value=value)

def parse_request(data: dict[str, Any]) -> ExtractRequest:
    if not isinstance(data, dict):
        raise ServiceError("INVALID_REQUEST", "request body must be json object")
    ssh_data = data.get("ssh") or {}
    selector_data = data.get("selector") or {}
    options_data = data.get("options") or {}
    ssh = SSHInfo(
        host=ssh_data.get("host") or ssh_data.get("node_ip") or "",
        port=int(ssh_data.get("port") or ssh_data.get("node_port") or 22),
        username=ssh_data.get("username") or ssh_data.get("node_user") or "root",
        private_key=ssh_data.get("private_key"), private_key_path=ssh_data.get("private_key_path"),
        password=ssh_data.get("password"), timeout=int(ssh_data.get("timeout") or 15),
    )
    if not ssh.host or not ssh.username:
        raise ServiceError("INVALID_REQUEST", "ssh.host and ssh.username are required")
    selector = Selector(
        namespace=selector_data.get("namespace") or selector_data.get("namespace_fragment") or "sop",
        pod=selector_data.get("pod") or selector_data.get("pod_fragment") or "aico",
        container=selector_data.get("container") or selector_data.get("container_fragment") or "aico",
    )
    if not selector.namespace or not selector.pod or not selector.container:
        raise ServiceError("INVALID_REQUEST", "selector.namespace/pod/container are required")
    raw_segments = data.get("path_segments") or [
        {"mode": MODE_EXACT, "value": "opt"}, {"mode": MODE_EXACT, "value": "log"},
        {"mode": MODE_EXACT, "value": "logs"}, {"mode": MODE_EXACT, "value": "textlog"},
        {"mode": MODE_REGEX, "value": "aico"}, {"mode": MODE_EXACT, "value": "log"},
        {"mode": MODE_EXACT, "value": "run"},
    ]
    if not isinstance(raw_segments, list) or not raw_segments:
        raise ServiceError("INVALID_REQUEST", "path_segments must be non-empty list")
    path_segments = [parse_segment(s, f"path_segments[{i}]") for i, s in enumerate(raw_segments)]
    log_file = parse_segment(data.get("log_file") or {"mode": MODE_REGEX, "value": "run"}, "log_file")
    chat_ids = data.get("chat_ids")
    if not isinstance(chat_ids, list) or not chat_ids or not all(isinstance(x, str) and x for x in chat_ids):
        raise ServiceError("INVALID_REQUEST", "chat_ids must be non-empty list[str]")
    chat_ids = list(dict.fromkeys(chat_ids))
    data_regex = data.get("data_regex")
    if data_regex is not None and (not isinstance(data_regex, str) or not data_regex):
        raise ServiceError("INVALID_REQUEST", "data_regex must be non-empty string when provided")
    return_mode = data.get("return_mode") or RETURN_MODE_VALUE
    if return_mode not in (RETURN_MODE_VALUE, RETURN_MODE_FULL_LINE, RETURN_MODE_MATCH):
        raise ServiceError("INVALID_REQUEST", "return_mode must be one of: value, full_line, match")
    real_time = parse_bool(options_data.get("real_time"), False)
    real_tail_bytes = int(options_data.get("real_tail_bytes") or DEFAULT_REAL_TAIL_BYTES)
    if real_tail_bytes <= 0 or real_tail_bytes > MAX_REAL_TAIL_BYTES:
        raise ServiceError("INVALID_REQUEST", f"options.real_tail_bytes must be in 1..{MAX_REAL_TAIL_BYTES}")
    if real_time and parse_bool(options_data.get("cache_only"), False):
        raise ServiceError("INVALID_REQUEST", "options.real_time and options.cache_only cannot both be true")
    options = Options(
        transfer_mode=options_data.get("transfer_mode") or TRANSFER_COMPATIBLE,
        cache_only=parse_bool(options_data.get("cache_only"), False),
        refresh_interval=int(options_data.get("refresh_interval") if options_data.get("refresh_interval") is not None else 60 * 3),
        pod_match_policy=options_data.get("pod_match_policy") or POD_MATCH_ALL,
        container_user=options_data.get("container_user"), real_time=real_time, real_tail_bytes=real_tail_bytes,
        max_matches_per_chat_id=int(options_data.get("max_matches_per_chat_id") or 10),
        max_log_files=int(options_data.get("max_log_files") or 200),
        max_single_file_size_mb=int(options_data.get("max_single_file_size_mb") or 2048),
        max_zip_entries=int(options_data.get("max_zip_entries") or 300),
        max_zip_uncompressed_size_mb=int(options_data.get("max_zip_uncompressed_size_mb") or 2048),
        zip_extract_cache_ttl_seconds=int(options_data.get("zip_extract_cache_ttl_seconds") or 86400),
        zip_extract_cache_max_size_mb=int(options_data.get("zip_extract_cache_max_size_mb") or 10240),
        regex_timeout_ms=int(options_data.get("regex_timeout_ms") or 100),
        cache_max_age_seconds=int(options_data.get("cache_max_age_seconds") or 86400),
        cache_max_size_mb=int(options_data.get("cache_max_size_mb") or 51200),
        cache_gc_interval_seconds=int(options_data.get("cache_gc_interval_seconds") or 300),
        remote_cmd_timeout=int(options_data.get("remote_cmd_timeout") or 300),
        copy_retry=int(options_data.get("copy_retry") or 1),
    )
    if options.transfer_mode not in (TRANSFER_COMPATIBLE, TRANSFER_STREAM):
        raise ServiceError("INVALID_REQUEST", "options.transfer_mode must be compatible or stream")
    if options.pod_match_policy not in (POD_MATCH_SINGLE, POD_MATCH_ALL):
        raise ServiceError("INVALID_REQUEST", "options.pod_match_policy must be single or all")
    if options.max_matches_per_chat_id <= 0:
        raise ServiceError("INVALID_REQUEST", "max_matches_per_chat_id must be greater than 0")
    if options.refresh_interval < 0:
        raise ServiceError("INVALID_REQUEST", "options.refresh_interval must be greater than or equal to 0")
    return ExtractRequest(
        ssh=ssh, selector=selector, path_segments=path_segments, log_file=log_file, chat_ids=chat_ids,
        data_regex=data_regex, field=data.get("field") or "intent", return_mode=return_mode,
        agent_service=data.get("agent_service") or "AICOServiceAgent", coarse_regex=data.get("coarse_regex"),
        trace=data.get("trace") or {}, options=options,
    )

def build_cache_entry(cache_key: str, batches: list[ResolvedLogBatch], files_dir: pathlib.Path, transfer_mode: str) -> dict[str, Any]:
    files = []
    resolved_sources = []
    for batch in batches:
        source_id = make_source_id(batch.target, batch.base_path)
        resolved_sources.append({
            "source_id": source_id, "namespace": batch.target.namespace, "pod": batch.target.pod,
            "pod_uid": batch.target.pod_uid, "container": batch.target.container,
            "container_id": batch.target.container_id, "base_path": batch.base_path,
        })
        for rf in batch.remote_files:
            local_path = files_dir / rf.source_id / rf.name
            files.append({
                "source_id": rf.source_id, "namespace": rf.namespace, "pod": rf.pod, "pod_uid": rf.pod_uid,
                "container": rf.container, "container_id": rf.container_id, "remote_path": rf.remote_path,
                "base_path": rf.base_path, "name": rf.name, "local_path": str(local_path),
                "mtime": rf.mtime, "size": rf.size, "fetched_at": now_ts(),
            })
    first = resolved_sources[0] if resolved_sources else {}
    return {
        "cache_key": cache_key, "created_at": now_ts(), "updated_at": now_ts(), "last_used_at": now_ts(),
        "transfer_mode": transfer_mode,
        "resolved": {k: first.get(k) for k in ("namespace", "pod", "pod_uid", "container", "container_id", "base_path")},
        "resolved_sources": resolved_sources, "files": files,
    }

def resolve_remote_files_for_request(ssh: SSHClientWrapper, req: ExtractRequest, warnings: list[WarningItem]) -> list[ResolvedLogBatch]:
    targets = resolve_k8s_targets(get_pods_json(ssh, req.options.remote_cmd_timeout), req.selector, req.options)
    batches = []
    errors = []
    total_files = 0
    for target in targets:
        try:
            base_path = resolve_base_path(ssh, target, req.path_segments, req.options)
            remote_files = list_remote_log_files(ssh, target, base_path, req.log_file, req.options)
            total_files += len(remote_files)
            if total_files > req.options.max_log_files:
                raise ServiceError("TOO_MANY_LOG_FILES_MATCHED", f"matched log files exceeded max_log_files={req.options.max_log_files}", details={"pod": target.pod, "total_files": total_files})
            batches.append(ResolvedLogBatch(target=target, base_path=base_path, remote_files=remote_files))
        except ServiceError as e:
            if req.options.pod_match_policy == POD_MATCH_ALL and e.code in ("PATH_SEGMENT_NOT_FOUND", "PATH_NOT_DIRECTORY", "LOG_FILE_NOT_FOUND", "ALL_LOG_FILES_TOO_LARGE"):
                warnings.append(WarningItem("POD_SOURCE_SKIPPED", f"skip pod {target.pod}: {e.code} {e.message}", details=e.details))
                errors.append({"pod": target.pod, "code": e.code, "message": e.message, "details": e.details})
                continue
            raise
    if not batches:
        raise ServiceError("NO_LOG_SOURCE_RESOLVED", "no pod resolved usable log files", details=errors)
    return batches

def stat_remote_log_batches(ssh: SSHClientWrapper, batches: list[ResolvedLogBatch], options: Options) -> list[ResolvedLogBatch]:
    result = []
    for batch in batches:
        files = stat_remote_log_files(ssh, batch.target, batch.base_path, batch.remote_files, options)
        if files:
            result.append(ResolvedLogBatch(target=batch.target, base_path=batch.base_path, remote_files=files))
    return result

def refresh_cache(ssh: SSHClientWrapper, req: ExtractRequest, cache_key: str, batches: list[ResolvedLogBatch], warnings: list[WarningItem]) -> dict[str, Any]:
    last_exc = None
    attempts = max(1, req.options.copy_retry + 1)
    current_batches = batches
    for idx in range(attempts):
        try:
            before = stat_remote_log_batches(ssh, current_batches, req.options) or current_batches
            files_dir, fetched_batches = fetch_logs(ssh, before, cache_key, req.options, warnings)
            after = stat_remote_log_batches(ssh, fetched_batches, req.options) or fetched_batches
            fetched_source_ids = {b.remote_files[0].source_id for b in fetched_batches if b.remote_files}
            before_fetched_only = [b for b in before if b.remote_files and b.remote_files[0].source_id in fetched_source_ids]
            if remote_batches_signature(before_fetched_only) != remote_batches_signature(after):
                warnings.append(WarningItem("FILE_CHANGED_DURING_COPY", "remote log file changed during copy; accept current fetched snapshot"))
            entry = build_cache_entry(cache_key, after, files_dir, req.options.transfer_mode)
            CACHE.set(cache_key, entry)
            return entry
        except ServiceError as e:
            last_exc = e
            if idx < attempts - 1:
                warnings.append(WarningItem("REFRESH_RETRY", f"refresh cache failed, retry {idx + 1}/{attempts - 1}", details={"code": e.code, "message": e.message, "details": e.details}))
                continue
            raise
    if last_exc:
        raise last_exc
    raise ServiceError("REMOTE_FETCH_FAILED", "refresh cache failed", http_status=502)

def make_empty_scan_result(req: ExtractRequest) -> dict[str, Any]:
    return {
        "items": [{"chat_id": chat_id, "conversation_id": None, "matches": [], "matched_count": 0} for chat_id in req.chat_ids],
        "missed_chat_ids": list(req.chat_ids), "scanned_files": 0,
    }

def handle_extract(req: ExtractRequest) -> dict[str, Any]:
    warnings: list[WarningItem] = []
    cache_key = build_cache_key(req)
    if req.options.real_time:
        try:
            with SSHClientWrapper(req.ssh) as ssh:
                batches = resolve_remote_files_for_request(ssh, req, warnings)
                scan_result, pseudo_entry = scan_remote_logs_real_time(ssh, req, batches, warnings)
                warnings.append(WarningItem("REAL_TIME_MODE", "real_time enabled; scanned remote log tail without local cache", details={"real_tail_bytes": req.options.real_tail_bytes, "matched_sources": len(batches)}))
                return make_success_response(req, cache_key, pseudo_entry, scan_result, False, True, warnings)
        except paramiko.AuthenticationException as e:
            raise ServiceError("SSH_AUTH_FAILED", f"ssh auth failed: {e}", http_status=502) from e
        except (paramiko.SSHException, OSError) as e:
            raise ServiceError("SSH_CONNECT_FAILED", f"ssh failed: {e}", http_status=502) from e
    cache_hit = False
    refetched = False
    entry = CACHE.get(cache_key)
    scan_result: Optional[dict[str, Any]] = None
    entry_fp = cache_entry_fingerprint(entry) if cache_files_exist(entry) else ""
    if cache_files_exist(entry):
        cache_hit = True
        scan_result = scan_logs(req, entry_to_local_files(entry), warnings)
        if not scan_result["missed_chat_ids"]:
            return make_success_response(req, cache_key, entry, scan_result, cache_hit, refetched, warnings)
    if req.options.cache_only:
        if cache_files_exist(entry):
            warnings.append(WarningItem("CACHE_ONLY_PARTIAL_MISS", "cache_only enabled; return cached scan result without remote refresh"))
            return make_success_response(req, cache_key, entry, scan_result or make_empty_scan_result(req), True, False, warnings)
        warnings.append(WarningItem("CACHE_ONLY_MISS", "cache_only enabled but no valid local cache found; skip remote refresh"))
        return make_success_response(req, cache_key, None, make_empty_scan_result(req), False, False, warnings)
    if cache_files_exist(entry) and should_skip_refresh_by_interval(entry, req.options):
        warnings.append(WarningItem("REFRESH_INTERVAL_NOT_REACHED", "refresh_interval not reached; return cached scan result without remote refresh", details={"remaining_seconds": round(cache_refresh_interval_remaining(entry, req.options), 3), "refresh_interval": req.options.refresh_interval}))
        return make_success_response(req, cache_key, entry, scan_result or make_empty_scan_result(req), True, False, warnings)
    with CACHE.key_lock(cache_key):
        locked_entry = CACHE.get(cache_key)
        locked_scan_result: Optional[dict[str, Any]] = None
        locked_fp = cache_entry_fingerprint(locked_entry) if cache_files_exist(locked_entry) else ""
        if cache_files_exist(locked_entry):
            cache_hit = True
            locked_scan_result = scan_result if locked_fp and locked_fp == entry_fp and scan_result is not None else scan_logs(req, entry_to_local_files(locked_entry), warnings)
            if not locked_scan_result["missed_chat_ids"]:
                return make_success_response(req, cache_key, locked_entry, locked_scan_result, True, False, warnings)
            if should_skip_refresh_by_interval(locked_entry, req.options):
                warnings.append(WarningItem("REFRESH_INTERVAL_NOT_REACHED", "refresh_interval not reached after lock; return cached scan result without remote refresh", details={"remaining_seconds": round(cache_refresh_interval_remaining(locked_entry, req.options), 3), "refresh_interval": req.options.refresh_interval}))
                return make_success_response(req, cache_key, locked_entry, locked_scan_result, True, False, warnings)
        try:
            with SSHClientWrapper(req.ssh) as ssh:
                batches = resolve_remote_files_for_request(ssh, req, warnings)
                if cache_files_exist(locked_entry) and remote_batches_signature(batches) == cached_signature(locked_entry):
                    if locked_scan_result is None:
                        locked_scan_result = scan_logs(req, entry_to_local_files(locked_entry), warnings)
                    return make_success_response(req, cache_key, locked_entry, locked_scan_result, True, False, warnings)
                entry = refresh_cache(ssh, req, cache_key, batches, warnings)
                refetched = True
        except paramiko.AuthenticationException as e:
            raise ServiceError("SSH_AUTH_FAILED", f"ssh auth failed: {e}", http_status=502) from e
        except (paramiko.SSHException, OSError) as e:
            raise ServiceError("SSH_CONNECT_FAILED", f"ssh failed: {e}", http_status=502) from e
        scan_result = scan_logs(req, entry_to_local_files(entry), warnings)
        return make_success_response(req, cache_key, entry, scan_result, cache_hit, refetched, warnings)

def make_success_response(req: ExtractRequest, cache_key: str, entry: Optional[dict[str, Any]], scan_result: dict[str, Any], cache_hit: bool, refetched: bool, warnings: list[WarningItem]) -> dict[str, Any]:
    resolved = (entry or {}).get("resolved", {})
    resolved_sources = (entry or {}).get("resolved_sources") or ([resolved] if resolved else [])
    files = (entry or {}).get("files", [])
    return {
        "success": True, "items": scan_result["items"], "missed_chat_ids": scan_result["missed_chat_ids"],
        "meta": {
            "trace": req.trace, "cache_key": cache_key, "cache_hit": cache_hit, "refetched": refetched,
            "namespace": resolved.get("namespace"), "pod": resolved.get("pod"), "pod_uid": resolved.get("pod_uid"),
            "container": resolved.get("container"), "container_id": resolved.get("container_id"),
            "real_time": req.options.real_time, "real_tail_bytes": req.options.real_tail_bytes,
            "base_path": resolved.get("base_path"), "resolved_sources": resolved_sources,
            "pod_count": len({s.get("pod") for s in resolved_sources if s.get("pod")}),
            "log_files": [{k: f.get(k) for k in ("source_id", "pod", "container", "remote_path", "local_path", "mtime", "size")} for f in files],
            "scanned_files": scan_result.get("scanned_files", 0), "transfer_mode": req.options.transfer_mode,
            "cache_only": req.options.cache_only, "refresh_interval": req.options.refresh_interval,
            "last_refresh_at": cache_last_refresh_ts(entry),
            "refresh_interval_remaining": round(cache_refresh_interval_remaining(entry, req.options), 3),
            "pod_match_policy": req.options.pod_match_policy,
            "zip_extract_cache_ttl_seconds": req.options.zip_extract_cache_ttl_seconds,
            "cache_mode": "real_time" if req.options.real_time else "cached", "return_mode": req.return_mode,
        },
        "warnings": [w.as_dict() for w in warnings], "error": None,
    }
