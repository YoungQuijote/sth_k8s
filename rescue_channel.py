#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SSH 失败或连接池饱和后的 kubectl 接应服务通道。"""

import dataclasses

from models import ExtractRequest, ServiceError

RESCUE_CHANNEL_BASE_URL = "http://{rescue_service_host}:{rescue_service_port}/api/v1/log/rescue/extract"
RESCUE_CHANNEL_TOKEN = ""
RESCUE_CHANNEL_VERIFY_TLS = False
RESCUE_FALLBACK_CODES = {
    "SSH_CONNECT_FAILED",
    "SSH_AUTH_FAILED",
    "SSH_POOL_QUEUE_FULL",
    "SSH_POOL_ACQUIRE_TIMEOUT",
}


def build_rescue_payload(req: ExtractRequest, source_error: ServiceError) -> dict:
    return {
        "chat_ids": list(req.chat_ids),
        "field": req.field,
        "selector": dataclasses.asdict(req.selector),
        "path_segments": [dataclasses.asdict(segment) for segment in req.path_segments],
        "log_file": dataclasses.asdict(req.log_file),
        "zip_member_file": {
            "mode": "regex",
            "value": r".*\.(?:log|txt)$",
        },
        "return_mode": req.return_mode,
        "options": {
            "real_tail_bytes": int(getattr(req.options, "real_tail_bytes", 4 * 1024 * 1024)),
            "max_matches_per_chat_id": req.options.max_matches_per_chat_id,
            "max_log_files": req.options.max_log_files,
            "max_zip_entries": req.options.max_zip_entries,
            "regex_timeout_ms": req.options.regex_timeout_ms,
            "command_timeout_seconds": min(req.options.remote_cmd_timeout, 600),
            "scan_timeout_seconds": 60,
            "pod_match_policy": req.options.pod_match_policy,
        },
        "trace": {
            **(req.trace or {}),
            "fallback_from": "k8s-log-fetcher",
            "fallback_error_code": source_error.code,
            "fallback_error_message": source_error.message,
        },
    }
