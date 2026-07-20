#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SQLite 查询请求解析。"""

from __future__ import annotations

import hmac
import os
from typing import Any, Optional

from common_utils import validate_basename_rule
from models import (
    MODE_CONTAINS, MODE_EXACT, MODE_REGEX, POD_MATCH_ALL, POD_MATCH_SINGLE,
    SQLITE_RESULT_MODE_ALL, SQLITE_RESULT_MODE_COLUMNS, SQLiteQueryOptions,
    SQLiteQueryRequest, SegmentRule, Selector, ServiceError, SSHInfo,
)
from sqlite_rule import SQLITE_QUERY_RULES

SQLITE_USER_SQL_AUTH_TOKEN = os.environ.get("SQLITE_USER_SQL_AUTH_TOKEN", "")
SERVICE_MAX_CHAT_IDS = max(1, int(os.environ.get("SQLITE_MAX_CHAT_IDS", "1000")))
SERVICE_MAX_PODS = max(1, int(os.environ.get("SQLITE_MAX_PODS", "64")))
SERVICE_MAX_SQL_LENGTH = max(1, int(os.environ.get("SQLITE_MAX_SQL_LENGTH", str(128 * 1024))))
SERVICE_MAX_RESULT_SIZE_BYTES = max(1, int(os.environ.get("SQLITE_MAX_RESULT_SIZE_BYTES", str(64 * 1024 * 1024))))
SERVICE_MAX_CELL_SIZE_BYTES = max(1, int(os.environ.get("SQLITE_MAX_CELL_SIZE_BYTES", str(16 * 1024 * 1024))))
SERVICE_MAX_ROWS = max(1, int(os.environ.get("SQLITE_MAX_TOTAL_ROWS", "50000")))
SERVICE_MAX_COLUMNS = max(1, int(os.environ.get("SQLITE_MAX_COLUMNS", "256")))

def _parse_int(
        value: Any,
        default: int,
        field_name: str,
        *,
        minimum: int = 1,
        maximum: Optional[int] = None,
) -> int:
    try:
        result = default if value is None else int(value)
    except (TypeError, ValueError) as exc:
        raise ServiceError("INVALID_REQUEST", f"{field_name} must be integer") from exc
    if result < minimum:
        raise ServiceError("INVALID_REQUEST", f"{field_name} must be >= {minimum}")
    if maximum is not None and result > maximum:
        raise ServiceError("INVALID_REQUEST", f"{field_name} must be <= {maximum}")
    return result


def _parse_segment(obj: Any, field_name: str) -> SegmentRule:
    if not isinstance(obj, dict):
        raise ServiceError("INVALID_REQUEST", f"{field_name} must be object")
    mode = obj.get("mode")
    value = obj.get("value")
    if mode not in {MODE_EXACT, MODE_CONTAINS, MODE_REGEX}:
        raise ServiceError("INVALID_REQUEST", f"{field_name}.mode must be exact, contains or regex")
    if not isinstance(value, str) or not value:
        raise ServiceError("INVALID_REQUEST", f"{field_name}.value must be non-empty string")
    rule = SegmentRule(mode=mode, value=value)
    validate_basename_rule(rule, f"{field_name}.value")
    return rule


def _parse_ssh(data: Any) -> SSHInfo:
    if not isinstance(data, dict):
        raise ServiceError("INVALID_REQUEST", "ssh must be object")
    try:
        port = int(data.get("port") or data.get("node_port") or 22)
        timeout = int(data.get("timeout") or 15)
    except (TypeError, ValueError) as exc:
        raise ServiceError("INVALID_REQUEST", "ssh.port/timeout must be integer") from exc
    info = SSHInfo(
        host=data.get("host") or data.get("node_ip") or "",
        port=port,
        username=data.get("username") or data.get("node_user") or "root",
        private_key=data.get("private_key"),
        private_key_path=data.get("private_key_path"),
        password=data.get("password"),
        timeout=timeout,
    )
    if not info.host or not info.username:
        raise ServiceError("INVALID_REQUEST", "ssh.host and ssh.username are required")
    if info.port <= 0 or info.port > 65535 or info.timeout <= 0:
        raise ServiceError("INVALID_REQUEST", "ssh.port/timeout is out of range")
    return info


def _parse_selector(data: Any) -> Selector:
    if not isinstance(data, dict):
        raise ServiceError("INVALID_REQUEST", "selector must be object")
    selector = Selector(
        namespace=data.get("namespace") or data.get("namespace_fragment") or "",
        pod=data.get("pod") or data.get("pod_fragment") or "",
        container=data.get("container") or data.get("container_fragment") or "",
    )
    if not selector.namespace or not selector.pod or not selector.container:
        raise ServiceError("INVALID_REQUEST", "selector.namespace/pod/container are required")
    return selector


def _resolve_sql(data: dict[str, Any], max_sql_length: int) -> tuple[str, str, Optional[str]]:
    field = data.get("field")
    user_sql = data.get("user_sql")
    user_sql_auth = data.get("user_sql_auth")
    has_field = isinstance(field, str) and bool(field)
    has_user_sql = isinstance(user_sql, str) and bool(user_sql.strip())
    if has_field == has_user_sql:
        raise ServiceError("INVALID_REQUEST", "exactly one of field or user_sql must be provided")

    if has_user_sql:
        if not SQLITE_USER_SQL_AUTH_TOKEN:
            raise ServiceError(
                "SQLITE_USER_SQL_NOT_CONFIGURED",
                "SQLITE_USER_SQL_AUTH_TOKEN is not configured",
                http_status=503,
            )
        if not isinstance(user_sql_auth, str) or not hmac.compare_digest(
            user_sql_auth,
            SQLITE_USER_SQL_AUTH_TOKEN,
        ):
            raise ServiceError(
                "SQLITE_USER_SQL_UNAUTHORIZED",
                "invalid user_sql_auth",
                http_status=403,
            )
        sql = user_sql.strip()
        query_source = "user_sql"
        resolved_field = None
    else:
        if user_sql_auth is not None:
            raise ServiceError("INVALID_REQUEST", "user_sql_auth is only valid with user_sql")
        spec = SQLITE_QUERY_RULES.get(field)
        if spec is None:
            raise ServiceError(
                "SQLITE_FIELD_NOT_FOUND",
                f"sqlite query field is not configured: {field}",
                http_status=404,
                details={"available_fields": sorted(SQLITE_QUERY_RULES)},
            )
        sql = spec.sql.strip()
        query_source = "field"
        resolved_field = field

    if "\x00" in sql:
        raise ServiceError("INVALID_REQUEST", "sql must not contain NUL")
    if len(sql.encode("utf-8")) > max_sql_length:
        raise ServiceError("INVALID_REQUEST", f"sql exceeded max_sql_length={max_sql_length}")
    if ":chat_id" not in sql:
        raise ServiceError(
            "SQLITE_CHAT_ID_PARAMETER_MISSING",
            "sql must contain named parameter :chat_id",
        )
    return sql, query_source, resolved_field


def parse_sqlite_query_request(data: Any) -> SQLiteQueryRequest:
    if not isinstance(data, dict):
        raise ServiceError("INVALID_REQUEST", "request body must be JSON object")

    options_data = data.get("options") or {}
    if not isinstance(options_data, dict):
        raise ServiceError("INVALID_REQUEST", "options must be object")
    pod_match_policy = options_data.get("pod_match_policy") or POD_MATCH_ALL
    if pod_match_policy not in {POD_MATCH_SINGLE, POD_MATCH_ALL}:
        raise ServiceError("INVALID_REQUEST", "options.pod_match_policy must be single or all")

    max_sql_length = _parse_int(
        options_data.get("max_sql_length"),
        128 * 1024,
        "options.max_sql_length",
        maximum=SERVICE_MAX_SQL_LENGTH,
    )
    max_chat_ids = _parse_int(
        options_data.get("max_chat_ids"),
        100,
        "options.max_chat_ids",
        maximum=SERVICE_MAX_CHAT_IDS,
    )
    max_pods = _parse_int(
        options_data.get("max_pods"),
        32,
        "options.max_pods",
        maximum=SERVICE_MAX_PODS,
    )
    max_rows_per_chat_id = _parse_int(
        options_data.get("max_rows_per_chat_id"),
        1000,
        "options.max_rows_per_chat_id",
        maximum=SERVICE_MAX_ROWS,
    )
    max_total_rows = _parse_int(
        options_data.get("max_total_rows"),
        5000,
        "options.max_total_rows",
        maximum=SERVICE_MAX_ROWS,
    )
    if max_rows_per_chat_id > max_total_rows:
        raise ServiceError(
            "INVALID_REQUEST",
            "options.max_rows_per_chat_id must be <= options.max_total_rows",
        )

    options = SQLiteQueryOptions(
        pod_match_policy=pod_match_policy,
        container_user=options_data.get("container_user"),
        sqlite_busy_timeout_ms=_parse_int(
            options_data.get("sqlite_busy_timeout_ms"),
            5000,
            "options.sqlite_busy_timeout_ms",
            maximum=60000,
        ),
        query_timeout_seconds=_parse_int(
            options_data.get("query_timeout_seconds"),
            30,
            "options.query_timeout_seconds",
            maximum=600,
        ),
        max_chat_ids=max_chat_ids,
        max_pods=max_pods,
        max_rows_per_chat_id=max_rows_per_chat_id,
        max_total_rows=max_total_rows,
        max_result_size_bytes=_parse_int(
            options_data.get("max_result_size_bytes"),
            16 * 1024 * 1024,
            "options.max_result_size_bytes",
            maximum=SERVICE_MAX_RESULT_SIZE_BYTES,
        ),
        max_cell_size_bytes=_parse_int(
            options_data.get("max_cell_size_bytes"),
            4 * 1024 * 1024,
            "options.max_cell_size_bytes",
            maximum=SERVICE_MAX_CELL_SIZE_BYTES,
        ),
        max_sql_length=max_sql_length,
        max_sqlite_file_size_mb=_parse_int(
            options_data.get("max_sqlite_file_size_mb"),
            4096,
            "options.max_sqlite_file_size_mb",
            maximum=65536,
        ),
        regex_timeout_ms=_parse_int(
            options_data.get("regex_timeout_ms"),
            100,
            "options.regex_timeout_ms",
            maximum=5000,
        ),
        remote_cmd_timeout=_parse_int(
            options_data.get("remote_cmd_timeout"),
            40,
            "options.remote_cmd_timeout",
            maximum=900,
        ),
    )

    chat_ids = data.get("chat_ids")
    if not isinstance(chat_ids, list) or not chat_ids:
        raise ServiceError("INVALID_REQUEST", "chat_ids must be non-empty list[str]")
    if not all(isinstance(item, str) and item for item in chat_ids):
        raise ServiceError("INVALID_REQUEST", "chat_ids must be non-empty list[str]")
    chat_ids = list(dict.fromkeys(chat_ids))
    if len(chat_ids) > options.max_chat_ids:
        raise ServiceError(
            "INVALID_REQUEST",
            f"chat_ids exceeded options.max_chat_ids={options.max_chat_ids}",
        )

    raw_segments = data.get("path_segments")
    if not isinstance(raw_segments, list):
        raise ServiceError("INVALID_REQUEST", "path_segments must be list")
    path_segments = [
        _parse_segment(item, f"path_segments[{index}]")
        for index, item in enumerate(raw_segments)
    ]
    sqlite_file = _parse_segment(
        data.get("sqlite_file") or {
            "mode": MODE_REGEX,
            "value": r".*\.(?:db|sqlite|sqlite3)$",
        },
        "sqlite_file",
    )

    result_mode = data.get("result_mode") or SQLITE_RESULT_MODE_ALL
    if result_mode not in {SQLITE_RESULT_MODE_ALL, SQLITE_RESULT_MODE_COLUMNS}:
        raise ServiceError("INVALID_REQUEST", "result_mode must be all or columns")
    columns = data.get("columns") or []
    if not isinstance(columns, list) or not all(isinstance(item, str) and item for item in columns):
        raise ServiceError("INVALID_REQUEST", "columns must be list[str]")
    columns = list(dict.fromkeys(columns))
    if len(columns) > SERVICE_MAX_COLUMNS or any(len(item) > 512 for item in columns):
        raise ServiceError("INVALID_REQUEST", "columns exceeded service limit")
    if result_mode == SQLITE_RESULT_MODE_COLUMNS and not columns:
        raise ServiceError("INVALID_REQUEST", "columns mode requires non-empty columns")
    if result_mode == SQLITE_RESULT_MODE_ALL and columns:
        raise ServiceError("INVALID_REQUEST", "columns must be empty when result_mode=all")

    sql, query_source, field = _resolve_sql(data, options.max_sql_length)
    trace = data.get("trace") or {}
    if not isinstance(trace, dict):
        raise ServiceError("INVALID_REQUEST", "trace must be object")

    return SQLiteQueryRequest(
        ssh=_parse_ssh(data.get("ssh") or {}),
        selector=_parse_selector(data.get("selector") or {}),
        path_segments=path_segments,
        sqlite_file=sqlite_file,
        chat_ids=chat_ids,
        sql=sql,
        query_source=query_source,
        field=field,
        result_mode=result_mode,
        columns=columns,
        trace=trace,
        options=options,
    )
