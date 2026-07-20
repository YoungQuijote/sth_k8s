#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SQLite 数据源定位与容器内查询。"""

from __future__ import annotations

import dataclasses
import json
from typing import Any

from common_utils import basename_match, q, sha256_text, stable_json
from k8s_resolver import get_pods_json, list_child_entries, resolve_base_path, resolve_k8s_targets
from models import POD_MATCH_ALL, ResolvedSQLiteSource, SQLiteQueryRequest, ServiceError, WarningItem
from preset_scripts import SQLITE_QUERY_RESULT_MARKER, SQLITE_QUERY_SCRIPT
from ssh_utils import SSHClientWrapper, kubectl_exec_cmd

def _source_id(req: SQLiteQueryRequest, target, sqlite_path: str) -> str:
    return sha256_text(stable_json({
        "host": req.ssh.host,
        "port": req.ssh.port,
        "namespace": target.namespace,
        "pod": target.pod,
        "pod_uid": target.pod_uid or target.pod,
        "container": target.container,
        "sqlite_path": sqlite_path,
    }))[:20]


def resolve_sqlite_sources(
        ssh: SSHClientWrapper,
        req: SQLiteQueryRequest,
        warnings: list[WarningItem],
) -> list[ResolvedSQLiteSource]:
    targets = resolve_k8s_targets(
        get_pods_json(ssh, req.options.remote_cmd_timeout),
        req.selector,
        req.options,
    )
    if len(targets) > req.options.max_pods:
        raise ServiceError(
            "TOO_MANY_PODS_MATCHED",
            f"pod selector exceeded max_pods={req.options.max_pods}",
            details={"matched": len(targets)},
        )

    sources: list[ResolvedSQLiteSource] = []
    skipped: list[dict[str, Any]] = []
    for target in targets:
        try:
            base_path = resolve_base_path(ssh, target, req.path_segments, req.options)
            entries = list_child_entries(ssh, target, base_path, "file", req.options)
            hits = [
                item for item in entries
                if basename_match(item["name"], req.sqlite_file, req.options.regex_timeout_ms)
            ]
            if not hits:
                raise ServiceError(
                    "SQLITE_FILE_NOT_FOUND",
                    f"sqlite file rule matched nothing at {base_path}",
                    http_status=404,
                    details={"pod": target.pod, "rule": dataclasses.asdict(req.sqlite_file)},
                )
            if len(hits) > 1:
                raise ServiceError(
                    "MULTIPLE_SQLITE_FILES_MATCHED",
                    "sqlite file rule must match exactly one file per pod",
                    details={"pod": target.pod, "files": [item["name"] for item in hits[:100]]},
                )
            item = hits[0]
            max_size = req.options.max_sqlite_file_size_mb * 1024 * 1024
            if item["size"] > max_size:
                raise ServiceError(
                    "SQLITE_FILE_TOO_LARGE",
                    "sqlite file exceeded max_sqlite_file_size_mb",
                    details={"pod": target.pod, "size": item["size"], "limit": max_size},
                )
            sqlite_path = base_path.rstrip("/") + "/" + item["name"]
            sources.append(ResolvedSQLiteSource(
                target=target,
                base_path=base_path,
                sqlite_path=sqlite_path,
                sqlite_name=item["name"],
                mtime=item["mtime"],
                size=item["size"],
                source_id=_source_id(req, target, sqlite_path),
            ))
        except ServiceError as exc:
            if req.options.pod_match_policy == POD_MATCH_ALL and exc.code in {
                "PATH_NOT_DIRECTORY",
                "PATH_SEGMENT_NOT_FOUND",
                "SQLITE_FILE_NOT_FOUND",
                "MULTIPLE_SQLITE_FILES_MATCHED",
                "SQLITE_FILE_TOO_LARGE",
            }:
                detail = {
                    "pod": target.pod,
                    "container": target.container,
                    "code": exc.code,
                    "message": exc.message,
                    "details": exc.details,
                }
                skipped.append(detail)
                warnings.append(WarningItem(
                    "SQLITE_SOURCE_SKIPPED",
                    f"skip pod {target.pod}: {exc.code} {exc.message}",
                    details=detail,
                ))
                continue
            raise

    if not sources:
        raise ServiceError(
            "NO_SQLITE_SOURCE_RESOLVED",
            "no pod resolved exactly one usable sqlite file",
            http_status=404,
            details=skipped,
        )
    return sources


def _extract_script_result(stdout: str) -> dict[str, Any]:
    for line in reversed(stdout.splitlines()):
        if line.startswith(SQLITE_QUERY_RESULT_MARKER):
            try:
                payload = json.loads(line[len(SQLITE_QUERY_RESULT_MARKER):])
            except Exception as exc:
                raise ServiceError(
                    "SQLITE_RESULT_PARSE_FAILED",
                    f"cannot parse sqlite query result JSON: {exc}",
                    http_status=502,
                ) from exc
            if not isinstance(payload, dict):
                raise ServiceError("SQLITE_RESULT_PARSE_FAILED", "sqlite result must be object", http_status=502)
            return payload
    raise ServiceError(
        "SQLITE_RESULT_MARKER_NOT_FOUND",
        "sqlite query script did not return result marker",
        http_status=502,
        details={"stdout_tail": stdout[-4000:]},
    )


def _remote_error_status(code: str) -> int:
    if code == "SQLITE_QUERY_TIMEOUT":
        return 504
    if code in {"SQLITE_BUSY_TIMEOUT", "SQLITE_SOURCE_QUEUE_FULL", "SQLITE_SOURCE_ACQUIRE_TIMEOUT"}:
        return 503
    if code in {
        "SQLITE_ROWS_LIMIT_EXCEEDED",
        "SQLITE_RESULT_SIZE_LIMIT_EXCEEDED",
        "SQLITE_CELL_SIZE_LIMIT_EXCEEDED",
    }:
        return 413
    if code in {"SQLITE_DATABASE_INVALID"}:
        return 422
    return 400


def execute_sqlite_source(
        ssh: SSHClientWrapper,
        req: SQLiteQueryRequest,
        source: ResolvedSQLiteSource,
) -> dict[str, Any]:
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
    inner = f"exec python3 -c {q(SQLITE_QUERY_SCRIPT)} {q(source.sqlite_path)}"
    command = kubectl_exec_cmd(
        source.target,
        inner,
        req.options.container_user,
        stdin=True,
    )
    stdout, stderr, code = ssh.run_with_input(
        command,
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
        timeout=max(req.options.remote_cmd_timeout, req.options.query_timeout_seconds + 5),
        check=False,
    )
    if code != 0:
        lower = stderr.lower()
        if "python3" in lower and ("not found" in lower or "no such file" in lower):
            error_code = "SQLITE_PYTHON_NOT_AVAILABLE"
        elif "no module named" in lower and "sqlite3" in lower:
            error_code = "SQLITE_MODULE_NOT_AVAILABLE"
        else:
            error_code = "SQLITE_REMOTE_EXEC_FAILED"
        raise ServiceError(
            error_code,
            f"container sqlite query command failed with exit code {code}",
            http_status=502,
            details={
                "pod": source.target.pod,
                "container": source.target.container,
                "sqlite_path": source.sqlite_path,
                "stderr": stderr[-4000:],
                "stdout": stdout[-4000:],
            },
        )

    result = _extract_script_result(stdout)
    if not result.get("success"):
        error = result.get("error") or {}
        error_code = str(error.get("code") or "SQLITE_QUERY_FAILED")
        raise ServiceError(
            error_code,
            str(error.get("message") or "sqlite query failed"),
            http_status=_remote_error_status(error_code),
            details={
                "source": {
                    "pod": source.target.pod,
                    "container": source.target.container,
                    "sqlite_path": source.sqlite_path,
                },
                "cause": error.get("details"),
            },
        )
    return result
