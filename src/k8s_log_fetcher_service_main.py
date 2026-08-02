#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Flask App"""

from __future__ import annotations

import os
import traceback
from typing import Any

import requests
from flask import Flask, jsonify, request
from loguru import logger

from src.models import APP_NAME, APP_VERSION, ServiceError
from src.utils.common_utils import now_ts
from src.main_loop import parse_request, handle_extract
from src.sqlite_tool.sqlite_query import parse_sqlite_query_request, handle_sqlite_query
from src.sqlite_tool.sqlite_rule import SQLITE_QUERY_RULES
from src.export_tool.file_export import handle_file_export
from src.export_tool.file_export_request import parse_file_export_request
from src.rescue_channel.rescue_channel import (
    RESCUE_CHANNEL_BASE_URL,
    SQLITE_RESCUE_CHANNEL_BASE_URL,
    RESCUE_CHANNEL_TOKEN,
    RESCUE_CHANNEL_VERIFY_TLS,
    RESCUE_FALLBACK_CODES,
    SQLITE_RESCUE_FALLBACK_CODES,
    build_rescue_payload,
    build_sqlite_rescue_payload,
)

app = Flask(__name__)


def make_service_error_response(
        error: ServiceError,
        req: Any = None,
        *,
        warnings: list[dict] | None = None,
):
    return jsonify({
        "success": False,
        "items": [],
        "missed_chat_ids": list(req.chat_ids) if req else [],
        "meta": {"trace": req.trace if req else {}},
        "warnings": warnings or [],
        "error": {
            "code": error.code,
            "message": error.message,
            "details": error.details,
        },
    }), error.http_status


def call_rescue_channel(
        *,
        url: str,
        payload: dict[str, Any],
        source_error: ServiceError,
        req: Any,
        read_timeout: float,
        channel_name: str,
):
    try:
        rescue_resp = requests.post(
            url=url,
            json=payload,
            headers={
                "Authorization": f"Bearer {RESCUE_CHANNEL_TOKEN}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            timeout=(3, read_timeout),
            verify=RESCUE_CHANNEL_VERIFY_TLS,
        )
        try:
            rescue_data = rescue_resp.json()
        except ValueError as json_error:
            raise RuntimeError(
                f"{channel_name} returned non-JSON response: "
                f"status={rescue_resp.status_code}, body={rescue_resp.text[-2000:]}"
            ) from json_error
        if not isinstance(rescue_data, dict):
            raise RuntimeError(
                f"{channel_name} response must be a JSON object, "
                f"got {type(rescue_data).__name__}"
            )
        logger.info(
            "{} completed: source_error={}, status={}, success={}",
            channel_name,
            source_error.code,
            rescue_resp.status_code,
            rescue_data.get("success"),
        )
        return jsonify(rescue_data), rescue_resp.status_code
    except requests.RequestException as rescue_error:
        logger.exception("{} transport error: {}", channel_name, rescue_error)
        return make_service_error_response(
            source_error,
            req,
            warnings=[{
                "code": "RESCUE_CHANNEL_FAILED",
                "message": f"{channel_name} request failed",
                "details": str(rescue_error),
            }],
        )
    except Exception as rescue_error:
        logger.exception("{} unexpected error: {}", channel_name, rescue_error)
        return make_service_error_response(
            source_error,
            req,
            warnings=[{
                "code": "RESCUE_CHANNEL_FAILED",
                "message": f"{channel_name} failed unexpectedly",
                "details": str(rescue_error),
            }],
        )


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "success": True,
        "service": APP_NAME,
        "version": APP_VERSION,
        "time": now_ts(),
        "sqlite_field_count": len(SQLITE_QUERY_RULES),
    })


@app.route("/api/v1/k8s/log/extract", methods=["POST"])
def extract_api():
    req = None
    try:
        payload = request.get_json(force=True, silent=False)
        req = parse_request(payload)
        return jsonify(handle_extract(req)), 200
    except ServiceError as se:
        logger.error("Internal ServiceError: code={}, message={}", se.code, se.message)
        if req is None or se.code not in RESCUE_FALLBACK_CODES:
            return make_service_error_response(se, req)
        rescue_url = RESCUE_CHANNEL_BASE_URL.format(
            rescue_service_host=req.ssh.host,
            rescue_service_port=38580,
        )
        return call_rescue_channel(
            url=rescue_url,
            payload=build_rescue_payload(req, se),
            source_error=se,
            req=req,
            read_timeout=70,
            channel_name="log rescue channel",
        )
    except Exception as ue:
        logger.exception("Internal UnexpectedError: {}", ue)
        return jsonify({
            "success": False,
            "items": [],
            "missed_chat_ids": list(req.chat_ids) if req else [],
            "meta": {"trace": req.trace if req else {}},
            "warnings": [],
            "error": {
                "code": "INTERNAL_ERROR",
                "message": str(ue),
                "details": traceback.format_exc(limit=8),
            },
        }), 500


@app.route("/api/v1/k8s/sqlite/query", methods=["POST"])
def sqlite_query_api():
    req = None
    try:
        payload = request.get_json(force=True, silent=False)
        req = parse_sqlite_query_request(payload)
        return jsonify(handle_sqlite_query(req)), 200
    except ServiceError as se:
        logger.error("SQLite ServiceError: code={}, message={}", se.code, se.message)
        if req is None or se.code not in SQLITE_RESCUE_FALLBACK_CODES:
            return make_service_error_response(se, req)
        rescue_url = SQLITE_RESCUE_CHANNEL_BASE_URL.format(
            rescue_service_host=req.ssh.host,
            rescue_service_port=38580,
        )
        return call_rescue_channel(
            url=rescue_url,
            payload=build_sqlite_rescue_payload(req, se),
            source_error=se,
            req=req,
            read_timeout=max(70, req.options.query_timeout_seconds + 20),
            channel_name="sqlite rescue channel",
        )
    except Exception as ue:
        logger.exception("SQLite UnexpectedError: {}", ue)
        return jsonify({
            "success": False,
            "items": [],
            "missed_chat_ids": list(req.chat_ids) if req else [],
            "meta": {"trace": req.trace if req else {}},
            "warnings": [],
            "error": {
                "code": "INTERNAL_ERROR",
                "message": str(ue),
                "details": traceback.format_exc(limit=8),
            },
        }), 500


@app.route("/api/v1/k8s/files/export", methods=["POST"])
def files_export_api():
    req = None
    try:
        payload = request.get_json(force=True, silent=False)
        req = parse_file_export_request(payload)
        return jsonify(handle_file_export(req)), 200
    except Exception as fe:
        logger.exception("Files UnexpectedError: {}", fe)
        return jsonify({
            "success": False,
            "items": [],
            "meta": {"trace": req.trace if req else {}},
            "warnings": [],
            "error": {
                "code": "INTERNAL_ERROR",
                "message": str(fe),
                "details": traceback.format_exc(limit=8),
            },
        }), 500


if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "38575"))
    debug = os.environ.get("DEBUG", "false").lower() == "true"
    app.run(host=host, port=port, debug=debug, threaded=True)
