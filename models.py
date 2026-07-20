#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""基础变量/结构体"""

import os
from dataclasses import dataclass, field as dc_field
from typing import Any, Literal, Optional

APP_NAME = "k8s-log-fetcher"
APP_VERSION = "2026.06.02-multi-pod-zip-cache-refresh-interval"
DEFAULT_CACHE_ROOT = os.environ.get("K8S_LOG_FETCHER_CACHE", "./tmp/k8s-log-fetcher-cache")
DEFAULT_REMOTE_TMP_PREFIX = "/tmp/k8s-log-fetcher."
DEFAULT_REAL_TAIL_BYTES = 4 * 1024 * 1024
MAX_REAL_TAIL_BYTES = 128 * 1024 * 1024
MODE_EXACT = "exact"
MODE_CONTAINS = "contains"
MODE_REGEX = "regex"
TRANSFER_COMPATIBLE = "compatible"
TRANSFER_STREAM = "stream"
RETURN_MODE_VALUE = "value"
RETURN_MODE_FULL_LINE = "full_line"
RETURN_MODE_MATCH = "match"
POD_MATCH_SINGLE = "single"
POD_MATCH_ALL = "all"

class ServiceError(RuntimeError):
    def __init__(self, code: str, message: str, *, http_status: int = 400, details: Optional[Any] = None):
        self.code = code
        self.message = message
        self.http_status = http_status
        self.details = details
        super().__init__(f"[{code}] {message}")

@dataclass
class WarningItem:
    code: str
    message: str
    file: Optional[str] = None
    details: Optional[Any] = None
    def as_dict(self) -> dict[str, Any]:
        data = {"code": self.code, "message": self.message}
        if self.file is not None:
            data["file"] = self.file
        if self.details is not None:
            data["details"] = self.details
        return data

@dataclass(frozen=True)
class SSHInfo:
    host: str
    port: int
    username: str
    private_key: Optional[str] = None
    private_key_path: Optional[str] = None
    password: Optional[str] = None
    timeout: int = 15

@dataclass(frozen=True)
class Selector:
    namespace: str
    pod: str
    container: str

@dataclass(frozen=True)
class SegmentRule:
    mode: Literal["exact", "contains", "regex"]
    value: str

@dataclass(frozen=True)
class Options:
    transfer_mode: Literal["compatible", "stream"] = TRANSFER_COMPATIBLE
    cache_only: bool = False
    refresh_interval: int = 60 * 3
    pod_match_policy: Literal["single", "all"] = POD_MATCH_ALL
    real_time: bool = False
    real_tail_bytes: int = DEFAULT_REAL_TAIL_BYTES
    container_user: Optional[str] = None
    max_matches_per_chat_id: int = 3
    max_log_files: int = 200
    max_single_file_size_mb: int = 2048
    max_zip_entries: int = 100
    max_zip_uncompressed_size_mb: int = 2048
    zip_extract_cache_ttl_seconds: int = 86400
    zip_extract_cache_max_size_mb: int = 10240
    regex_timeout_ms: int = 100
    cache_max_age_seconds: int = 86400 * 3
    cache_max_size_mb: int = 51200
    cache_gc_interval_seconds: int = 300
    remote_cmd_timeout: int = 300
    copy_retry: int = 1

@dataclass(frozen=True)
class ExtractRequest:
    ssh: SSHInfo
    selector: Selector
    path_segments: list[SegmentRule]
    log_file: SegmentRule
    chat_ids: list[str]
    field: str
    agent_service: Optional[str] = None
    coarse_regex: Optional[str] = None
    data_regex: Optional[str] = None
    return_mode: Literal["value", "full_line", "match"] = RETURN_MODE_VALUE
    trace: dict[str, Any] = dc_field(default_factory=dict)
    options: Options = dc_field(default_factory=Options)

@dataclass
class K8sTarget:
    namespace: str
    pod: str
    pod_uid: Optional[str]
    container: str
    container_id: Optional[str]

@dataclass
class RemoteLogFile:
    remote_path: str
    base_path: str
    name: str
    mtime: float
    size: int
    source_id: str
    namespace: str
    pod: str
    pod_uid: Optional[str]
    container: str
    container_id: Optional[str]

@dataclass
class LocalLogFile:
    local_path: str
    remote_path: str
    name: str
    mtime: float
    size: int
    source_id: str = ""
    namespace: str = ""
    pod: str = ""
    pod_uid: Optional[str] = None
    container: str = ""
    container_id: Optional[str] = None

@dataclass
class ResolvedLogBatch:
    target: K8sTarget
    base_path: str
    remote_files: list[RemoteLogFile]
