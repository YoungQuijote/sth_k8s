#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SQLite field -> SQL 服务端规则。"""

from __future__ import annotations

import importlib.util
import os
from typing import Any

from src.models import SQLiteQuerySpec

# 在这里配置固定查询，SQL 必须使用命名参数 :chat_id。
SQLITE_QUERY_RULES: dict[str, SQLiteQuerySpec] = {}


def _normalize_rules(raw: Any, source: str) -> dict[str, SQLiteQuerySpec]:
    if not isinstance(raw, dict):
        raise RuntimeError(f"{source} must define SQLITE_QUERY_RULES as dict")
    result: dict[str, SQLiteQuerySpec] = {}
    for field, value in raw.items():
        if not isinstance(field, str) or not field:
            raise RuntimeError(f"{source} contains invalid field name")
        if isinstance(value, str):
            spec = SQLiteQuerySpec(sql=value)
        elif isinstance(value, SQLiteQuerySpec):
            spec = value
        elif isinstance(value, dict) and isinstance(value.get("sql"), str):
            spec = SQLiteQuerySpec(
                sql=value["sql"],
                description=str(value.get("description") or ""),
            )
        else:
            raise RuntimeError(f"{source}[{field!r}] must be str, SQLiteQuerySpec or dict")
        if not spec.sql.strip():
            raise RuntimeError(f"{source}[{field!r}].sql must be non-empty")
        result[field] = spec
    return result


def load_external_query_rules(path: str) -> dict[str, SQLiteQuerySpec]:
    spec = importlib.util.spec_from_file_location("sqlite_query_rules_external", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load sqlite query rules module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return _normalize_rules(getattr(module, "SQLITE_QUERY_RULES", None), path)


_external_rules_path = os.environ.get("SQLITE_QUERY_RULES_FILE", "").strip()
if _external_rules_path:
    SQLITE_QUERY_RULES.update(load_external_query_rules(_external_rules_path))
