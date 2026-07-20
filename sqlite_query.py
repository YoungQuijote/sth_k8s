#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Kubernetes 容器内 SQLite 只读查询编排。"""

from __future__ import annotations

import json
import time
from typing import Any

import paramiko

from models import POD_MATCH_ALL, ResolvedSQLiteSource, SQLiteQueryRequest, ServiceError, WarningItem
from sqlite_concurrency import SQLITE_SOURCE_LIMITER
from sqlite_remote import execute_sqlite_source, resolve_sqlite_sources
from sqlite_request import parse_sqlite_query_request
from ssh_utils import SSHClientWrapper

__all__ = ["parse_sqlite_query_request", "handle_sqlite_query"]

def _convert_ssh_error(exc: BaseException) -> ServiceError:
    if isinstance(exc, paramiko.AuthenticationException):
        return ServiceError("SSH_AUTH_FAILED", f"ssh auth failed: {exc}", http_status=502)
    return ServiceError("SSH_CONNECT_FAILED", f"ssh failed: {exc}", http_status=502)


def handle_sqlite_query(req: SQLiteQueryRequest) -> dict[str, Any]:
    started_at = time.monotonic()
    warnings: list[WarningItem] = []
    try:
        with SSHClientWrapper(req.ssh) as ssh:
            sources = resolve_sqlite_sources(ssh, req, warnings)
    except (paramiko.AuthenticationException, paramiko.SSHException, OSError) as exc:
        raise _convert_ssh_error(exc) from exc

    source_results: list[tuple[ResolvedSQLiteSource, dict[str, Any]]] = []
    source_errors: list[dict[str, Any]] = []
    accumulated_rows = 0
    accumulated_result_bytes = 0
    fatal_codes = {
        "SQLITE_SOURCE_QUEUE_FULL",
        "SQLITE_SOURCE_ACQUIRE_TIMEOUT",
        "SQLITE_ROWS_LIMIT_EXCEEDED",
        "SQLITE_RESULT_SIZE_LIMIT_EXCEEDED",
        "SQLITE_CELL_SIZE_LIMIT_EXCEEDED",
    }

    for source in sources:
        try:
            limiter_key = f"{req.ssh.host}:{req.ssh.port}:{source.source_id}"
            with SQLITE_SOURCE_LIMITER.acquire(limiter_key):
                try:
                    with SSHClientWrapper(req.ssh) as ssh:
                        result = execute_sqlite_source(ssh, req, source)
                except (paramiko.AuthenticationException, paramiko.SSHException, OSError) as exc:
                    raise _convert_ssh_error(exc) from exc

            next_rows = accumulated_rows + int(result.get("total_rows") or 0)
            if next_rows > req.options.max_total_rows:
                raise ServiceError(
                    "SQLITE_ROWS_LIMIT_EXCEEDED",
                    "all sqlite sources exceeded max_total_rows",
                    http_status=413,
                    details={"limit": req.options.max_total_rows},
                )
            result_bytes = len(
                json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            )
            next_result_bytes = accumulated_result_bytes + result_bytes
            if next_result_bytes > req.options.max_result_size_bytes:
                raise ServiceError(
                    "SQLITE_RESULT_SIZE_LIMIT_EXCEEDED",
                    "all sqlite sources exceeded max_result_size_bytes",
                    http_status=413,
                    details={"limit": req.options.max_result_size_bytes},
                )
            accumulated_rows = next_rows
            accumulated_result_bytes = next_result_bytes
            source_results.append((source, result))
        except ServiceError as exc:
            if exc.code in fatal_codes or exc.code in {
                "SSH_CONNECT_FAILED", "SSH_AUTH_FAILED", "SSH_POOL_QUEUE_FULL", "SSH_POOL_ACQUIRE_TIMEOUT",
            }:
                raise
            detail = {
                "source_id": source.source_id,
                "pod": source.target.pod,
                "container": source.target.container,
                "sqlite_path": source.sqlite_path,
                "code": exc.code,
                "message": exc.message,
                "details": exc.details,
            }
            if req.options.pod_match_policy == POD_MATCH_ALL:
                source_errors.append(detail)
                warnings.append(WarningItem(
                    "SQLITE_SOURCE_QUERY_FAILED",
                    f"query failed for pod {source.target.pod}: {exc.code} {exc.message}",
                    details=detail,
                ))
                continue
            raise

    if not source_results:
        raise ServiceError(
            "NO_SQLITE_SOURCE_QUERY_SUCCEEDED",
            "all resolved sqlite source queries failed",
            http_status=502,
            details=source_errors,
        )

    aggregated: dict[str, dict[str, Any]] = {
        chat_id: {"chat_id": chat_id, "sources": [], "source_count": 0, "row_count": 0}
        for chat_id in req.chat_ids
    }
    resolved_sources = []
    total_rows = 0
    for source, result in source_results:
        source_meta = {
            "source_id": source.source_id,
            "namespace": source.target.namespace,
            "pod": source.target.pod,
            "pod_uid": source.target.pod_uid,
            "container": source.target.container,
            "container_id": source.target.container_id,
            "base_path": source.base_path,
            "sqlite_path": source.sqlite_path,
            "mtime": source.mtime,
            "size": source.size,
        }
        resolved_sources.append(source_meta)
        for item in result.get("items") or []:
            chat_id = item.get("chat_id")
            if chat_id not in aggregated:
                continue
            row_count = int(item.get("row_count") or 0)
            total_rows += row_count
            if row_count:
                aggregated[chat_id]["sources"].append({
                    **source_meta,
                    "columns": item.get("columns") or [],
                    "rows": item.get("rows") or [],
                    "row_count": row_count,
                })
                aggregated[chat_id]["source_count"] += 1
                aggregated[chat_id]["row_count"] += row_count

    items = [aggregated[chat_id] for chat_id in req.chat_ids]
    missed = [chat_id for chat_id in req.chat_ids if not aggregated[chat_id]["row_count"]]
    response = {
        "success": True,
        "items": items,
        "missed_chat_ids": missed,
        "meta": {
            "trace": req.trace,
            "mode": "remote_sqlite",
            "query_source": req.query_source,
            "field": req.field,
            "result_mode": req.result_mode,
            "columns": req.columns,
            "resolved_sources": resolved_sources,
            "pod_count": len({item["pod"] for item in resolved_sources}),
            "successful_source_count": len(source_results),
            "failed_source_count": len(source_errors),
            "total_rows": total_rows,
            "elapsed_ms": round((time.monotonic() - started_at) * 1000, 3),
        },
        "warnings": [item.as_dict() for item in warnings],
        "error": None,
    }
    if len(json.dumps(response, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > req.options.max_result_size_bytes:
        raise ServiceError(
            "SQLITE_RESULT_SIZE_LIMIT_EXCEEDED",
            "final sqlite response exceeded max_result_size_bytes",
            http_status=413,
            details={"limit": req.options.max_result_size_bytes},
        )
    return response
