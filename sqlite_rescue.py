#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""为现有 Kubernetes 日志接应服务注册 SQLite 只读查询路由。"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import threading
import time
from typing import Any

from flask import Blueprint, Flask, jsonify, request

from preset_scripts import SQLITE_QUERY_RESULT_MARKER, SQLITE_QUERY_SCRIPT
from sqlite_rescue_runtime import (
    ALLOW_NO_AUTH, RESCUE_TOKEN, MAX_REQUEST_BYTES, POD_MATCH_ALL,
    SQLiteRescueRequest, SQLiteSource, ServiceError, WarningItem,
    basename_match, parse_request,
)
from sqlite_rescue_kube import (
    KubectlRunner, canonical_root, list_entries, resolve_base, resolve_targets, target_root,
)

MAX_CONCURRENT_QUERIES = max(1, int(os.environ.get("LOG_RESCUE_MAX_CONCURRENT_SQLITE_QUERIES", "4")))
SOURCE_MAX_CONCURRENCY = max(1, int(os.environ.get("LOG_RESCUE_SQLITE_SOURCE_MAX_CONCURRENCY", "2")))
SOURCE_MAX_WAITERS = max(0, int(os.environ.get("LOG_RESCUE_SQLITE_SOURCE_MAX_WAITERS", "100")))
SOURCE_WAIT_TIMEOUT = max(0.001, float(os.environ.get("LOG_RESCUE_SQLITE_SOURCE_ACQUIRE_TIMEOUT_SECONDS", "30")))
_QUERY_SEMAPHORE = threading.BoundedSemaphore(MAX_CONCURRENT_QUERIES)


class _SourceLimiter:
    def __init__(self):
        self._guard = threading.Lock()
        self._semaphores: dict[str, threading.BoundedSemaphore] = {}
        self._waiters = 0

    @contextlib.contextmanager
    def acquire(self, key: str):
        with self._guard:
            semaphore = self._semaphores.setdefault(key, threading.BoundedSemaphore(SOURCE_MAX_CONCURRENCY))
        if semaphore.acquire(blocking=False):
            try:
                yield
            finally:
                semaphore.release()
            return
        with self._guard:
            if self._waiters >= SOURCE_MAX_WAITERS:
                raise ServiceError("SQLITE_SOURCE_QUEUE_FULL", "sqlite rescue source queue is full", http_status=503)
            self._waiters += 1
        try:
            acquired = semaphore.acquire(timeout=SOURCE_WAIT_TIMEOUT)
        finally:
            with self._guard:
                self._waiters -= 1
        if not acquired:
            raise ServiceError("SQLITE_SOURCE_ACQUIRE_TIMEOUT", "sqlite rescue source wait timed out", http_status=503)
        try:
            yield
        finally:
            semaphore.release()


_SOURCE_LIMITER = _SourceLimiter()


def _authenticate() -> None:
    if ALLOW_NO_AUTH:
        return
    if not RESCUE_TOKEN:
        raise ServiceError("SERVICE_NOT_CONFIGURED", "LOG_RESCUE_TOKEN is not configured", http_status=503)
    authorization = request.headers.get("Authorization", "")
    bearer = authorization.removeprefix("Bearer ").strip() if authorization.startswith("Bearer ") else ""
    token = bearer or request.headers.get("X-Rescue-Token", "")
    if not token or not hmac.compare_digest(token, RESCUE_TOKEN):
        raise ServiceError("UNAUTHORIZED", "invalid rescue token", http_status=401)


def _resolve_sources(runner: KubectlRunner, req: SQLiteRescueRequest) -> tuple[list[SQLiteSource], list[WarningItem]]:
    warnings: list[WarningItem] = []
    sources = []
    skipped = []
    for target in resolve_targets(runner, req):
        try:
            root = canonical_root(runner, target, target_root(target), req.options)
            base = resolve_base(runner, target, root, req)
            hits = [item for item in list_entries(runner, target, base, "file", req.options) if basename_match(item["name"], req.sqlite_file, req.options.regex_timeout_ms)]
            if not hits:
                raise ServiceError("SQLITE_FILE_NOT_FOUND", f"sqlite file matched nothing at {base}", http_status=404)
            if len(hits) != 1:
                raise ServiceError("MULTIPLE_SQLITE_FILES_MATCHED", "sqlite file must match exactly one file", details=[item["name"] for item in hits[:100]])
            item = hits[0]
            limit = req.options.max_sqlite_file_size_mb * 1024 * 1024
            if item["size"] > limit:
                raise ServiceError("SQLITE_FILE_TOO_LARGE", "sqlite file exceeded configured size", details={"size": item["size"], "limit": limit})
            path = base.rstrip("/") + "/" + item["name"]
            digest = hashlib.sha256(f"{target.namespace}\0{target.pod_uid or target.pod}\0{target.container}\0{path}".encode()).hexdigest()[:20]
            sources.append(SQLiteSource(target, root, base, path, item["name"], item["mtime"], item["size"], digest))
        except ServiceError as exc:
            if req.options.pod_match_policy == POD_MATCH_ALL and exc.code in {
                "CONTAINER_ROOT_NOT_FOUND", "PATH_NOT_DIRECTORY", "PATH_SEGMENT_NOT_FOUND",
                "SQLITE_FILE_NOT_FOUND", "MULTIPLE_SQLITE_FILES_MATCHED", "SQLITE_FILE_TOO_LARGE",
            }:
                detail = {"pod": target.pod, "container": target.container, "code": exc.code, "message": exc.message, "details": exc.details}
                skipped.append(detail)
                warnings.append(WarningItem("SQLITE_SOURCE_SKIPPED", f"skip pod {target.pod}: {exc.code} {exc.message}", detail))
                continue
            raise
    if not sources:
        raise ServiceError("NO_SQLITE_SOURCE_RESOLVED", "no pod resolved usable sqlite source", http_status=404, details=skipped)
    return sources, warnings


def _script_result(stdout: str) -> dict[str, Any]:
    for line in reversed(stdout.splitlines()):
        if line.startswith(SQLITE_QUERY_RESULT_MARKER):
            try:
                result = json.loads(line[len(SQLITE_QUERY_RESULT_MARKER):])
            except Exception as exc:
                raise ServiceError("SQLITE_RESULT_PARSE_FAILED", str(exc), http_status=502) from exc
            if isinstance(result, dict):
                return result
    raise ServiceError("SQLITE_RESULT_MARKER_NOT_FOUND", "sqlite result marker not found", http_status=502, details=stdout[-4000:])


def _execute(runner: KubectlRunner, req: SQLiteRescueRequest, source: SQLiteSource) -> dict[str, Any]:
    payload = {
        "sql": req.sql,
        "chat_ids": req.chat_ids,
        "result_mode": req.result_mode,
        "columns": req.columns,
        "sqlite_busy_timeout_ms": req.options.sqlite_busy_timeout_ms,
        "query_timeout_seconds": req.options.query_timeout_seconds,
        "limits": {
            "max_rows_per_chat_id": req.options.max_rows_per_chat_id,
            "max_total_rows": req.options.max_total_rows,
            "max_result_size_bytes": req.options.max_result_size_bytes,
            "max_cell_size_bytes": req.options.max_cell_size_bytes,
        },
    }
    with _SOURCE_LIMITER.acquire(source.source_id):
        result = runner.exec(
            source.target,
            ["python3", "-c", SQLITE_QUERY_SCRIPT, source.sqlite_path],
            timeout=max(req.options.command_timeout_seconds, req.options.query_timeout_seconds + 5),
            input_data=json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(),
            check=False,
        )
    if result.returncode != 0:
        lower = result.stderr_text.lower()
        code = "SQLITE_PYTHON_NOT_AVAILABLE" if "python3" in lower and ("not found" in lower or "no such file" in lower) else "SQLITE_REMOTE_EXEC_FAILED"
        raise ServiceError(code, "container sqlite rescue command failed", http_status=502, details={"stderr": result.stderr_text, "stdout": result.stdout_text[-4000:]})
    payload = _script_result(result.stdout_text)
    if not payload.get("success"):
        error = payload.get("error") or {}
        code = str(error.get("code") or "SQLITE_QUERY_FAILED")
        status = 504 if code == "SQLITE_QUERY_TIMEOUT" else 503 if code == "SQLITE_BUSY_TIMEOUT" else 413 if code.endswith("LIMIT_EXCEEDED") else 400
        raise ServiceError(code, str(error.get("message") or "sqlite query failed"), http_status=status, details=error.get("details"))
    return payload


def execute_request(req: SQLiteRescueRequest) -> dict[str, Any]:
    started = time.monotonic()
    runner = KubectlRunner()
    sources, warnings = _resolve_sources(runner, req)
    successes = []
    errors = []
    aggregate_rows = 0
    aggregate_bytes = 0
    for source in sources:
        try:
            result = _execute(runner, req, source)
            aggregate_rows += int(result.get("total_rows") or 0)
            aggregate_bytes += len(json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode())
            if aggregate_rows > req.options.max_total_rows:
                raise ServiceError("SQLITE_ROWS_LIMIT_EXCEEDED", "all rescue sources exceeded max_total_rows", http_status=413)
            if aggregate_bytes > req.options.max_result_size_bytes:
                raise ServiceError("SQLITE_RESULT_SIZE_LIMIT_EXCEEDED", "all rescue sources exceeded max_result_size_bytes", http_status=413)
            successes.append((source, result))
        except ServiceError as exc:
            if exc.code.endswith("LIMIT_EXCEEDED") or exc.code in {"SQLITE_SOURCE_QUEUE_FULL", "SQLITE_SOURCE_ACQUIRE_TIMEOUT"}:
                raise
            detail = {"source_id": source.source_id, "pod": source.target.pod, "container": source.target.container, "sqlite_path": source.sqlite_path, "code": exc.code, "message": exc.message, "details": exc.details}
            if req.options.pod_match_policy == POD_MATCH_ALL:
                errors.append(detail)
                warnings.append(WarningItem("SQLITE_SOURCE_QUERY_FAILED", f"query failed for pod {source.target.pod}: {exc.code} {exc.message}", detail))
                continue
            raise
    if not successes:
        raise ServiceError("NO_SQLITE_SOURCE_QUERY_SUCCEEDED", "all sqlite rescue source queries failed", http_status=502, details=errors)

    items = {chat_id: {"chat_id": chat_id, "sources": [], "source_count": 0, "row_count": 0} for chat_id in req.chat_ids}
    resolved = []
    for source, result in successes:
        meta = {
            "source_id": source.source_id, "namespace": source.target.namespace, "pod": source.target.pod,
            "pod_uid": source.target.pod_uid, "node_name": source.target.node_name,
            "container": source.target.container, "container_id": source.target.container_id,
            "root_path": source.root_path, "base_path": source.base_path, "sqlite_path": source.sqlite_path,
            "mtime": source.mtime, "size": source.size,
        }
        resolved.append(meta)
        for result_item in result.get("items") or []:
            chat_id = result_item.get("chat_id")
            if chat_id not in items:
                continue
            count = int(result_item.get("row_count") or 0)
            if count:
                items[chat_id]["sources"].append({**meta, "columns": result_item.get("columns") or [], "rows": result_item.get("rows") or [], "row_count": count})
                items[chat_id]["source_count"] += 1
                items[chat_id]["row_count"] += count
    result_items = [items[chat_id] for chat_id in req.chat_ids]
    return {
        "success": True,
        "items": result_items,
        "missed_chat_ids": [chat_id for chat_id in req.chat_ids if not items[chat_id]["row_count"]],
        "meta": {
            "trace": req.trace, "mode": "kubectl_sqlite_rescue", "query_source": req.query_source,
            "field": req.field, "result_mode": req.result_mode, "columns": req.columns,
            "resolved_sources": resolved, "successful_source_count": len(successes),
            "failed_source_count": len(errors), "total_rows": aggregate_rows,
            "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
        },
        "warnings": [item.as_dict() for item in warnings],
        "error": None,
    }


def register_sqlite_rescue(app: Flask) -> None:
    """在既有接应 Flask app 上注册 `/api/v1/sqlite/rescue/query`。"""
    app.config["MAX_CONTENT_LENGTH"] = max(int(app.config.get("MAX_CONTENT_LENGTH") or 0), MAX_REQUEST_BYTES)
    blueprint = Blueprint("sqlite_rescue", __name__)

    @blueprint.post("/api/v1/sqlite/rescue/query")
    def sqlite_rescue_query():
        acquired = False
        try:
            _authenticate()
            acquired = _QUERY_SEMAPHORE.acquire(blocking=False)
            if not acquired:
                raise ServiceError("TOO_MANY_REQUESTS", "sqlite rescue concurrency limit reached", http_status=429)
            req = parse_request(request.get_json(silent=False))
            return jsonify(execute_request(req)), 200
        except ServiceError as exc:
            return jsonify({
                "success": False, "items": [], "missed_chat_ids": [], "meta": {}, "warnings": [],
                "error": {"code": exc.code, "message": exc.message, "details": exc.details},
            }), exc.http_status
        except Exception as exc:  # pragma: no cover
            return jsonify({
                "success": False, "items": [], "missed_chat_ids": [], "meta": {}, "warnings": [],
                "error": {"code": "INTERNAL_ERROR", "message": str(exc), "details": None},
            }), 500
        finally:
            if acquired:
                _QUERY_SEMAPHORE.release()

    app.register_blueprint(blueprint)
