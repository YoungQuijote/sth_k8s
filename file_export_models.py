#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Kubernetes 容器文件导出请求模型。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Optional

from models import SegmentRule, Selector, SSHInfo, TRANSFER_COMPATIBLE, POD_MATCH_ALL

OVERWRITE_REJECT = "reject"
OVERWRITE_REPLACE = "replace"
DEFAULT_SHOW_LIMIT = 32 * 1024
MAX_SHOW_LIMIT = 1024 * 1024


@dataclass(frozen=True)
class FileExportOptions:
    transfer_mode: Literal["compatible", "stream"] = TRANSFER_COMPATIBLE
    pod_match_policy: Literal["single", "all"] = POD_MATCH_ALL
    container_user: Optional[str] = None
    max_pods: int = 32
    max_files: int = 200
    max_single_file_size_mb: int = 2048
    max_total_size_mb: int = 4096
    regex_timeout_ms: int = 100
    remote_cmd_timeout: int = 300
    copy_retry: int = 1
    show_details: bool = False
    show_decode: str = "utf-8"
    show_limit: int = DEFAULT_SHOW_LIMIT


@dataclass(frozen=True)
class FileExportRequest:
    ssh: SSHInfo
    selector: Selector
    source_root: str
    source_root_key: Optional[str]
    source_root_custom: bool
    mixed_dir_segments: list[SegmentRule]
    file_rules: list[SegmentRule]
    storage_root: str
    storage_root_custom: bool
    relative_dir: str
    overwrite_policy: Literal["reject", "replace"] = OVERWRITE_REJECT
    trace: dict[str, Any] = field(default_factory=dict)
    options: FileExportOptions = field(default_factory=FileExportOptions)
