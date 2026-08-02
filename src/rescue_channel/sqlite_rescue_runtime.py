#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""kubectl SQLite 接应服务的模型、配置、解析与容器路径定位。"""

from __future__ import annotations

import dataclasses
import fnmatch
import json
import os
import pathlib
import re as std_re
import socket
import subprocess
from dataclasses import dataclass, field as dc_field
from typing import Any, Literal, Optional

try:
    import regex as safe_re  # type: ignore
except Exception:  # pragma: no cover
    safe_re = None

MODE_EXACT = "exact"
MODE_CONTAINS = "contains"
MODE_REGEX = "regex"
POD_MATCH_SINGLE = "single"
POD_MATCH_ALL = "all"
RESULT_ALL = "all"
RESULT_COLUMNS = "columns"

KUBECTL_BIN = os.environ.get("LOG_RESCUE_KUBECTL", "kubectl").strip() or "kubectl"
KUBECONFIG = os.environ.get("LOG_RESCUE_KUBECONFIG", os.environ.get("KUBECONFIG", "")).strip()
KUBECTL_CONTEXT = os.environ.get("LOG_RESCUE_KUBECTL_CONTEXT", "").strip()
NODE_NAME = os.environ.get("LOG_RESCUE_NODE_NAME", "").strip() or socket.gethostname()
DEFAULT_CONTAINER_ROOT = os.environ.get("LOG_RESCUE_CONTAINER_ROOT", "/").strip() or "/"
MAX_REQUEST_BYTES = max(1, int(os.environ.get("LOG_RESCUE_MAX_REQUEST_BYTES", 2 * 1024 * 1024)))
MAX_PATH_SEGMENTS = max(1, int(os.environ.get("LOG_RESCUE_MAX_PATH_SEGMENTS", 32)))
MAX_SELECTOR_TARGETS = max(1, int(os.environ.get("LOG_RESCUE_MAX_SELECTOR_TARGETS", 32)))
MAX_STDERR_BYTES = max(1, int(os.environ.get("LOG_RESCUE_MAX_STDERR_BYTES", 64 * 1024)))


def parse_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return default


DISABLE_NODE_SCOPE = parse_bool(os.environ.get("LOG_RESCUE_DISABLE_NODE_SCOPE"), False)
ALLOW_ANY_SELECTOR = parse_bool(os.environ.get("LOG_RESCUE_ALLOW_ANY_SELECTOR"), True)
ALLOW_NO_AUTH = parse_bool(os.environ.get("LOG_RESCUE_ALLOW_NO_AUTH"), True)
RESCUE_TOKEN = os.environ.get("LOG_RESCUE_TOKEN", "")


class ServiceError(RuntimeError):
    def __init__(self, code: str, message: str, *, http_status: int = 400, details: Any = None):
        self.code = code
        self.message = message
        self.http_status = http_status
        self.details = details
        super().__init__(f"[{code}] {message}")


@dataclass
class WarningItem:
    code: str
    message: str
    details: Any = None

    def as_dict(self) -> dict[str, Any]:
        result = {"code": self.code, "message": self.message}
        if self.details is not None:
            result["details"] = self.details
        return result


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
class Target:
    namespace: str
    pod: str
    pod_uid: Optional[str]
    node_name: Optional[str]
    container: str
    container_id: Optional[str]


@dataclass(frozen=True)
class SelectorPolicy:
    namespace: str
    pod: str
    container: str
    root: Optional[str] = None

    def matches(self, target: Target) -> bool:
        return (
            fnmatch.fnmatchcase(target.namespace, self.namespace)
            and fnmatch.fnmatchcase(target.pod, self.pod)
            and fnmatch.fnmatchcase(target.container, self.container)
        )


@dataclass(frozen=True)
class SQLiteRescueOptions:
    sqlite_busy_timeout_ms: int = 5000
    query_timeout_seconds: int = 30
    max_chat_ids: int = 100
    max_pods: int = 32
    max_rows_per_chat_id: int = 1000
    max_total_rows: int = 5000
    max_result_size_bytes: int = 16 * 1024 * 1024
    max_cell_size_bytes: int = 4 * 1024 * 1024
    max_sql_length: int = 128 * 1024
    max_sqlite_file_size_mb: int = 4096
    regex_timeout_ms: int = 100
    command_timeout_seconds: int = 40
    pod_match_policy: Literal["single", "all"] = POD_MATCH_ALL


@dataclass(frozen=True)
class SQLiteRescueRequest:
    selector: Selector
    path_segments: list[SegmentRule]
    sqlite_file: SegmentRule
    chat_ids: list[str]
    sql: str
    query_source: Literal["field", "user_sql"]
    field: Optional[str]
    result_mode: Literal["all", "columns"]
    columns: list[str]
    trace: dict[str, Any] = dc_field(default_factory=dict)
    options: SQLiteRescueOptions = dc_field(default_factory=SQLiteRescueOptions)


@dataclass(frozen=True)
class SQLiteSource:
    target: Target
    root_path: str
    base_path: str
    sqlite_path: str
    sqlite_name: str
    mtime: float
    size: int
    source_id: str


@dataclass(frozen=True)
class CommandResult:
    stdout: bytes
    stderr: bytes
    returncode: int

    @property
    def stdout_text(self) -> str:
        return self.stdout.decode("utf-8", errors="replace")

    @property
    def stderr_text(self) -> str:
        return self.stderr.decode("utf-8", errors="replace")


def _load_policies(env_name: str, *, allow_root: bool) -> list[SelectorPolicy]:
    raw = os.environ.get(env_name, "").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{env_name} must be valid JSON: {exc}") from exc
    if not isinstance(data, list):
        raise RuntimeError(f"{env_name} must be JSON array")
    result = []
    for index, item in enumerate(data):
        if not isinstance(item, dict):
            raise RuntimeError(f"{env_name}[{index}] must be object")
        values = [item.get("namespace"), item.get("pod"), item.get("container")]
        if not all(isinstance(value, str) and value for value in values):
            raise RuntimeError(f"{env_name}[{index}] requires namespace/pod/container")
        root = item.get("root") if allow_root else None
        if root is not None and (not isinstance(root, str) or not root.startswith("/") or "\x00" in root):
            raise RuntimeError(f"{env_name}[{index}].root must be absolute path")
        result.append(SelectorPolicy(*values, root))
    return result


ALLOWED_SELECTORS = _load_policies("LOG_RESCUE_ALLOWED_SELECTORS", allow_root=False)
SELECTOR_ROOTS = _load_policies("LOG_RESCUE_SELECTOR_ROOTS", allow_root=True)


def _parse_positive_int(value: Any, default: int, field: str, maximum: int) -> int:
    try:
        result = default if value is None else int(value)
    except (TypeError, ValueError) as exc:
        raise ServiceError("INVALID_REQUEST", f"{field} must be integer") from exc
    if result <= 0 or result > maximum:
        raise ServiceError("INVALID_REQUEST", f"{field} must be in 1..{maximum}")
    return result


def _validate_rule(rule: SegmentRule, field: str) -> None:
    value = rule.value
    if not isinstance(value, str) or not value or "\x00" in value or len(value) > 4096:
        raise ServiceError("INVALID_REQUEST", f"{field} is invalid")
    if "/" in value:
        raise ServiceError("INVALID_REQUEST", f"{field} must match basename only")
    if rule.mode in {MODE_EXACT, MODE_CONTAINS} and ("\\" in value or value in {".", ".."}):
        raise ServiceError("INVALID_REQUEST", f"{field} must be basename-like")


def _parse_rule(value: Any, field: str) -> SegmentRule:
    if not isinstance(value, dict):
        raise ServiceError("INVALID_REQUEST", f"{field} must be object")
    rule = SegmentRule(value.get("mode"), value.get("value"))
    if rule.mode not in {MODE_EXACT, MODE_CONTAINS, MODE_REGEX}:
        raise ServiceError("INVALID_REQUEST", f"{field}.mode is invalid")
    _validate_rule(rule, f"{field}.value")
    return rule


def compile_pattern(pattern: str):
    try:
        return safe_re.compile(pattern) if safe_re is not None else std_re.compile(pattern)
    except Exception as exc:
        raise ServiceError("REGEX_COMPILE_FAILED", f"compile basename regex failed: {exc}") from exc


def basename_match(name: str, rule: SegmentRule, timeout_ms: int) -> bool:
    if rule.mode == MODE_EXACT:
        return name == rule.value
    if rule.mode == MODE_CONTAINS:
        return rule.value in name
    compiled = compile_pattern(rule.value)
    if safe_re is not None:
        try:
            return compiled.search(name, timeout=timeout_ms / 1000.0) is not None
        except TimeoutError as exc:
            raise ServiceError("REGEX_TIMEOUT", str(exc)) from exc
    return compiled.search(name) is not None


def parse_request(data: Any) -> SQLiteRescueRequest:
    if not isinstance(data, dict):
        raise ServiceError("INVALID_REQUEST", "request body must be JSON object")
    selector_data = data.get("selector") or {}
    if not isinstance(selector_data, dict):
        raise ServiceError("INVALID_REQUEST", "selector must be object")
    selector = Selector(
        selector_data.get("namespace") or "",
        selector_data.get("pod") or "",
        selector_data.get("container") or "",
    )
    if not selector.namespace or not selector.pod or not selector.container:
        raise ServiceError("INVALID_REQUEST", "selector.namespace/pod/container are required")

    raw_segments = data.get("path_segments")
    if not isinstance(raw_segments, list) or len(raw_segments) > MAX_PATH_SEGMENTS:
        raise ServiceError("INVALID_REQUEST", "path_segments must be bounded list")
    path_segments = [_parse_rule(item, f"path_segments[{index}]") for index, item in enumerate(raw_segments)]
    sqlite_file = _parse_rule(data.get("sqlite_file") or {"mode": MODE_REGEX, "value": r".*\.(?:db|sqlite|sqlite3)$"}, "sqlite_file")

    options_data = data.get("options") or {}
    if not isinstance(options_data, dict):
        raise ServiceError("INVALID_REQUEST", "options must be object")
    pod_policy = options_data.get("pod_match_policy") or POD_MATCH_ALL
    if pod_policy not in {POD_MATCH_SINGLE, POD_MATCH_ALL}:
        raise ServiceError("INVALID_REQUEST", "pod_match_policy must be single or all")
    options = SQLiteRescueOptions(
        sqlite_busy_timeout_ms=_parse_positive_int(options_data.get("sqlite_busy_timeout_ms"), 5000, "sqlite_busy_timeout_ms", 60000),
        query_timeout_seconds=_parse_positive_int(options_data.get("query_timeout_seconds"), 30, "query_timeout_seconds", 600),
        max_chat_ids=_parse_positive_int(options_data.get("max_chat_ids"), 100, "max_chat_ids", 1000),
        max_pods=_parse_positive_int(options_data.get("max_pods"), 32, "max_pods", MAX_SELECTOR_TARGETS),
        max_rows_per_chat_id=_parse_positive_int(options_data.get("max_rows_per_chat_id"), 1000, "max_rows_per_chat_id", 50000),
        max_total_rows=_parse_positive_int(options_data.get("max_total_rows"), 5000, "max_total_rows", 50000),
        max_result_size_bytes=_parse_positive_int(options_data.get("max_result_size_bytes"), 16 * 1024 * 1024, "max_result_size_bytes", 64 * 1024 * 1024),
        max_cell_size_bytes=_parse_positive_int(options_data.get("max_cell_size_bytes"), 4 * 1024 * 1024, "max_cell_size_bytes", 16 * 1024 * 1024),
        max_sql_length=_parse_positive_int(options_data.get("max_sql_length"), 128 * 1024, "max_sql_length", 128 * 1024),
        max_sqlite_file_size_mb=_parse_positive_int(options_data.get("max_sqlite_file_size_mb"), 4096, "max_sqlite_file_size_mb", 65536),
        regex_timeout_ms=_parse_positive_int(options_data.get("regex_timeout_ms"), 100, "regex_timeout_ms", 5000),
        command_timeout_seconds=_parse_positive_int(options_data.get("command_timeout_seconds"), 40, "command_timeout_seconds", 900),
        pod_match_policy=pod_policy,
    )
    if options.max_rows_per_chat_id > options.max_total_rows:
        raise ServiceError("INVALID_REQUEST", "max_rows_per_chat_id must be <= max_total_rows")

    chat_ids = data.get("chat_ids")
    if not isinstance(chat_ids, list) or not chat_ids or not all(isinstance(item, str) and item for item in chat_ids):
        raise ServiceError("INVALID_REQUEST", "chat_ids must be non-empty list[str]")
    chat_ids = list(dict.fromkeys(chat_ids))
    if len(chat_ids) > options.max_chat_ids:
        raise ServiceError("INVALID_REQUEST", "chat_ids exceeded max_chat_ids")

    sql = data.get("sql")
    if not isinstance(sql, str) or not sql.strip() or "\x00" in sql:
        raise ServiceError("INVALID_REQUEST", "sql must be non-empty string")
    sql = sql.strip()
    if len(sql.encode("utf-8")) > options.max_sql_length or ":chat_id" not in sql:
        raise ServiceError("SQLITE_CHAT_ID_PARAMETER_MISSING", "sql must be bounded and contain :chat_id")
    query_source = data.get("query_source") or "field"
    if query_source not in {"field", "user_sql"}:
        raise ServiceError("INVALID_REQUEST", "query_source is invalid")
    field = data.get("field")
    if field is not None and not isinstance(field, str):
        raise ServiceError("INVALID_REQUEST", "field must be string")
    result_mode = data.get("result_mode") or RESULT_ALL
    columns = data.get("columns") or []
    if result_mode not in {RESULT_ALL, RESULT_COLUMNS} or not isinstance(columns, list) or not all(isinstance(item, str) and item for item in columns):
        raise ServiceError("INVALID_REQUEST", "result_mode/columns is invalid")
    columns = list(dict.fromkeys(columns))
    if (result_mode == RESULT_COLUMNS) != bool(columns):
        raise ServiceError("INVALID_REQUEST", "columns are required only in columns mode")
    trace = data.get("trace") or {}
    if not isinstance(trace, dict):
        raise ServiceError("INVALID_REQUEST", "trace must be object")
    return SQLiteRescueRequest(selector, path_segments, sqlite_file, chat_ids, sql, query_source, field, result_mode, columns, trace, options)
