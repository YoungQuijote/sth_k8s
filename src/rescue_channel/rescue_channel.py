#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SSH 失败或资源饱和后的 kubectl 接应服务通道。"""

import dataclasses

from src.models import ExtractRequest, SQLiteQueryRequest, ServiceError

RESCUE_CHANNEL_BASE_URL = "http://{rescue_service_host}:{rescue_service_port}/api/v1/log/rescue/extract"
SQLITE_RESCUE_CHANNEL_BASE_URL = "http://{rescue_service_host}:{rescue_service_port}/api/v1/sqlite/rescue/query"
RESCUE_CHANNEL_TOKEN = ""
RESCUE_CHANNEL_VERIFY_TLS = False
RESCUE_FALLBACK_CODES = {
    "SSH_CONNECT_FAILED",
    "SSH_AUTH_FAILED",
    "SSH_POOL_QUEUE_FULL",
    "SSH_POOL_ACQUIRE_TIMEOUT",
}
SQLITE_RESCUE_FALLBACK_CODES = {
    *RESCUE_FALLBACK_CODES,
    "SQLITE_SOURCE_QUEUE_FULL",
    "SQLITE_SOURCE_ACQUIRE_TIMEOUT",
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


def build_sqlite_rescue_payload(req: SQLiteQueryRequest, source_error: ServiceError) -> dict:
    """构造已鉴权、已解析 SQL 的接应载荷；不转发 user_sql_auth。"""
    return {
        "chat_ids": list(req.chat_ids),
        "sql": req.sql,
        "query_source": req.query_source,
        "field": req.field,
        "selector": dataclasses.asdict(req.selector),
        "path_segments": [dataclasses.asdict(segment) for segment in req.path_segments],
        "sqlite_file": dataclasses.asdict(req.sqlite_file),
        "result_mode": req.result_mode,
        "columns": list(req.columns),
        "options": {
            "sqlite_busy_timeout_ms": req.options.sqlite_busy_timeout_ms,
            "query_timeout_seconds": req.options.query_timeout_seconds,
            "max_chat_ids": req.options.max_chat_ids,
            "max_pods": req.options.max_pods,
            "max_rows_per_chat_id": req.options.max_rows_per_chat_id,
            "max_total_rows": req.options.max_total_rows,
            "max_result_size_bytes": req.options.max_result_size_bytes,
            "max_cell_size_bytes": req.options.max_cell_size_bytes,
            "max_sql_length": req.options.max_sql_length,
            "max_sqlite_file_size_mb": req.options.max_sqlite_file_size_mb,
            "regex_timeout_ms": req.options.regex_timeout_ms,
            "command_timeout_seconds": min(req.options.remote_cmd_timeout, 600),
            "pod_match_policy": req.options.pod_match_policy,
        },
        "trace": {
            **(req.trace or {}),
            "fallback_from": "k8s-log-fetcher-sqlite",
            "fallback_error_code": source_error.code,
            "fallback_error_message": source_error.message,
        },
    }
