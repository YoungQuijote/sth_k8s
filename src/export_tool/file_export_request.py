#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Kubernetes 文件导出 API 请求解析。"""

from __future__ import annotations

import codecs
import pathlib
from typing import Any

from src.utils.common_utils import parse_bool
from src.export_tool.file_export_models import (
    DEFAULT_SHOW_LIMIT,
    MAX_SHOW_LIMIT,
    OVERWRITE_REJECT,
    OVERWRITE_REPLACE,
    FileExportOptions,
    FileExportRequest,
)
from src.export_tool.file_export_rules import resolve_source_root, resolve_storage_root
from src.models import (
    MODE_CONTAINS,
    MODE_EXACT,
    MODE_REGEX,
    POD_MATCH_ALL,
    POD_MATCH_SINGLE,
    TRANSFER_COMPATIBLE,
    TRANSFER_STREAM,
    SegmentRule,
    Selector,
    ServiceError,
    SSHInfo,
)

MAX_EXPORT_PODS = 64
MAX_EXPORT_FILES = 2000
MAX_EXPORT_SINGLE_FILE_SIZE_MB = 4096
MAX_EXPORT_TOTAL_SIZE_MB = 16384


def _parse_positive_int(value: Any, default: int, field_name: str, maximum: int) -> int:
    if value is None:
        result = default
    else:
        try:
            result = int(value)
        except (TypeError, ValueError) as exc:
            raise ServiceError("INVALID_REQUEST", f"{field_name} must be integer") from exc
    if result <= 0 or result > maximum:
        raise ServiceError("INVALID_REQUEST", f"{field_name} must be in 1..{maximum}")
    return result


def _parse_non_negative_int(value: Any, default: int, field_name: str, maximum: int) -> int:
    if value is None:
        result = default
    else:
        try:
            result = int(value)
        except (TypeError, ValueError) as exc:
            raise ServiceError("INVALID_REQUEST", f"{field_name} must be integer") from exc
    if result < 0 or result > maximum:
        raise ServiceError("INVALID_REQUEST", f"{field_name} must be in 0..{maximum}")
    return result


def _parse_segment(value: Any, field_name: str) -> SegmentRule:
    if not isinstance(value, dict):
        raise ServiceError("INVALID_REQUEST", f"{field_name} must be object")
    mode = value.get("mode")
    pattern = value.get("value")
    if mode not in (MODE_EXACT, MODE_CONTAINS, MODE_REGEX):
        raise ServiceError("INVALID_REQUEST", f"{field_name}.mode must be exact, contains or regex")
    if not isinstance(pattern, str) or not pattern:
        raise ServiceError("INVALID_REQUEST", f"{field_name}.value must be non-empty string")
    return SegmentRule(mode=mode, value=pattern)


def _validate_relative_dir(value: Any) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise ServiceError("INVALID_REQUEST", "destination.relative_dir must be non-empty relative path")
    path = pathlib.PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ServiceError("INVALID_REQUEST", "destination.relative_dir must not escape storage root")
    normalized = path.as_posix()
    if normalized in ("", ".") or normalized.startswith("../") or "/../" in normalized:
        raise ServiceError("INVALID_REQUEST", "destination.relative_dir must not escape storage root")
    return normalized


def parse_file_export_request(data: dict[str, Any]) -> FileExportRequest:
    if not isinstance(data, dict):
        raise ServiceError("INVALID_REQUEST", "request body must be json object")

    ssh_data = data.get("ssh") or {}
    selector_data = data.get("selector") or {}
    source_data = data.get("source") or {}
    destination_data = data.get("destination") or {}
    options_data = data.get("options") or {}
    if not all(isinstance(x, dict) for x in (ssh_data, selector_data, source_data, destination_data, options_data)):
        raise ServiceError("INVALID_REQUEST", "ssh/selector/source/destination/options must be objects")

    try:
        ssh = SSHInfo(
            host=ssh_data.get("host") or ssh_data.get("node_ip") or "",
            port=int(ssh_data.get("port") or ssh_data.get("node_port") or 22),
            username=ssh_data.get("username") or ssh_data.get("node_user") or "root",
            private_key=ssh_data.get("private_key"),
            private_key_path=ssh_data.get("private_key_path"),
            password=ssh_data.get("password"),
            timeout=int(ssh_data.get("timeout") or 15),
        )
    except (TypeError, ValueError) as exc:
        raise ServiceError("INVALID_REQUEST", "ssh.port and ssh.timeout must be integers") from exc
    if not ssh.host or not ssh.username:
        raise ServiceError("INVALID_REQUEST", "ssh.host and ssh.username are required")

    selector = Selector(
        namespace=selector_data.get("namespace") or selector_data.get("namespace_fragment") or "",
        pod=selector_data.get("pod") or selector_data.get("pod_fragment") or "",
        container=selector_data.get("container") or selector_data.get("container_fragment") or "",
    )
    if not selector.namespace or not selector.pod or not selector.container:
        raise ServiceError("INVALID_REQUEST", "selector.namespace/pod/container are required")

    source_root, source_root_key, source_root_custom = resolve_source_root(
        source_data.get("root_key"),
        source_data.get("root_dir"),
        source_data.get("auth_token"),
    )
    raw_segments = source_data.get("mixed_dir_segments")
    if not isinstance(raw_segments, list) or not raw_segments:
        raise ServiceError("INVALID_REQUEST", "source.mixed_dir_segments must be non-empty list")
    mixed_dir_segments = [
        _parse_segment(item, f"source.mixed_dir_segments[{idx}]")
        for idx, item in enumerate(raw_segments)
    ]

    raw_file_rules = source_data.get("files")
    if not isinstance(raw_file_rules, list) or not raw_file_rules:
        raise ServiceError("INVALID_REQUEST", "source.files must be non-empty list")
    file_rules = [
        _parse_segment(item, f"source.files[{idx}]")
        for idx, item in enumerate(raw_file_rules)
    ]

    storage_root, storage_root_custom = resolve_storage_root(
        destination_data.get("storage_root"),
        destination_data.get("auth_token"),
    )
    relative_dir = _validate_relative_dir(destination_data.get("relative_dir"))
    overwrite_policy = destination_data.get("overwrite_policy") or OVERWRITE_REJECT
    if overwrite_policy not in (OVERWRITE_REJECT, OVERWRITE_REPLACE):
        raise ServiceError("INVALID_REQUEST", "destination.overwrite_policy must be reject or replace")

    transfer_mode = options_data.get("transfer_mode") or TRANSFER_COMPATIBLE
    if transfer_mode not in (TRANSFER_COMPATIBLE, TRANSFER_STREAM):
        raise ServiceError("INVALID_REQUEST", "options.transfer_mode must be compatible or stream")
    pod_match_policy = options_data.get("pod_match_policy") or POD_MATCH_ALL
    if pod_match_policy not in (POD_MATCH_SINGLE, POD_MATCH_ALL):
        raise ServiceError("INVALID_REQUEST", "options.pod_match_policy must be single or all")

    show_details = parse_bool(options_data.get("show_details"), False)
    show_decode = options_data.get("show_decode") or "utf-8"
    if not isinstance(show_decode, str) or not show_decode:
        raise ServiceError("INVALID_REQUEST", "options.show_decode must be non-empty codec name")
    try:
        codecs.lookup(show_decode)
    except LookupError as exc:
        raise ServiceError("INVALID_REQUEST", f"unknown options.show_decode codec: {show_decode}") from exc

    options = FileExportOptions(
        transfer_mode=transfer_mode,
        pod_match_policy=pod_match_policy,
        container_user=options_data.get("container_user"),
        max_pods=_parse_positive_int(options_data.get("max_pods"), 32, "options.max_pods", MAX_EXPORT_PODS),
        max_files=_parse_positive_int(options_data.get("max_files"), 200, "options.max_files", MAX_EXPORT_FILES),
        max_single_file_size_mb=_parse_positive_int(
            options_data.get("max_single_file_size_mb"),
            2048,
            "options.max_single_file_size_mb",
            MAX_EXPORT_SINGLE_FILE_SIZE_MB,
        ),
        max_total_size_mb=_parse_positive_int(
            options_data.get("max_total_size_mb"),
            4096,
            "options.max_total_size_mb",
            MAX_EXPORT_TOTAL_SIZE_MB,
        ),
        regex_timeout_ms=_parse_positive_int(options_data.get("regex_timeout_ms"), 100, "options.regex_timeout_ms", 60000),
        remote_cmd_timeout=_parse_positive_int(options_data.get("remote_cmd_timeout"), 300, "options.remote_cmd_timeout", 86400),
        copy_retry=_parse_non_negative_int(options_data.get("copy_retry"), 1, "options.copy_retry", 10),
        show_details=show_details,
        show_decode=show_decode,
        show_limit=_parse_positive_int(
            options_data.get("show_limit"),
            DEFAULT_SHOW_LIMIT,
            "options.show_limit",
            MAX_SHOW_LIMIT,
        ),
    )

    return FileExportRequest(
        ssh=ssh,
        selector=selector,
        source_root=source_root,
        source_root_key=source_root_key,
        source_root_custom=source_root_custom,
        mixed_dir_segments=mixed_dir_segments,
        file_rules=file_rules,
        storage_root=storage_root,
        storage_root_custom=storage_root_custom,
        relative_dir=relative_dir,
        overwrite_policy=overwrite_policy,
        trace=data.get("trace") or {},
        options=options,
    )
