#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Flask App"""

import os
import traceback

import requests
from flask import Flask, jsonify, request
from loguru import logger

from models import APP_NAME, APP_VERSION, ExtractRequest, ServiceError
from common_utils import now_ts
from main_loop import parse_request, handle_extract
from rescue_channel import (
    RESCUE_CHANNEL_BASE_URL,
    RESCUE_CHANNEL_TOKEN,
    RESCUE_CHANNEL_VERIFY_TLS,
    RESCUE_FALLBACK_CODES,
    build_rescue_payload,
)

app = Flask(__name__)

def make_service_error_response(error: ServiceError, req: ExtractRequest | None = None, *, warnings: list[dict] | None = None):
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

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"success": True, "service": APP_NAME, "version": APP_VERSION, "time": now_ts()})

@app.route("/api/v1/k8s/log/extract", methods=["POST"])
def extract_api():
    req: ExtractRequest | None = None
    try:
        payload = request.get_json(force=True, silent=False)
        req = parse_request(payload)
        response = handle_extract(req)
        return jsonify(response), 200
    except ServiceError as se:
        logger.error("Internal ServiceError: code={}, message={}", se.code, se.message)
        if req is None or se.code not in RESCUE_FALLBACK_CODES:
            return make_service_error_response(se, req)
        try:
            rescue_url = RESCUE_CHANNEL_BASE_URL.format(
                rescue_service_host=req.ssh.host,
                rescue_service_port=38580,
            )
            rescue_resp = requests.post(
                url=rescue_url,
                json=build_rescue_payload(req, se),
                headers={
                    "Authorization": f"Bearer {RESCUE_CHANNEL_TOKEN}",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                timeout=(3, 70),
                verify=RESCUE_CHANNEL_VERIFY_TLS,
            )
            try:
                rescue_data = rescue_resp.json()
            except ValueError as json_error:
                raise RuntimeError(
                    "rescue channel returned non-JSON response: "
                    f"status={rescue_resp.status_code}, body={rescue_resp.text[-2000:]}"
                ) from json_error
            if not isinstance(rescue_data, dict):
                raise RuntimeError(
                    "rescue channel response must be a JSON object, "
                    f"got {type(rescue_data).__name__}"
                )
            logger.info(
                "Rescue channel completed: source_error={}, status={}, success={}",
                se.code,
                rescue_resp.status_code,
                rescue_data.get("success"),
            )
            return jsonify(rescue_data), rescue_resp.status_code
        except requests.RequestException as rescue_error:
            logger.exception("Rescue channel transport error: {}", rescue_error)
            return make_service_error_response(
                se,
                req,
                warnings=[{
                    "code": "RESCUE_CHANNEL_FAILED",
                    "message": "rescue channel request failed",
                    "details": str(rescue_error),
                }],
            )
        except Exception as rescue_error:
            logger.exception("Rescue channel unexpected error: {}", rescue_error)
            return make_service_error_response(
                se,
                req,
                warnings=[{
                    "code": "RESCUE_CHANNEL_FAILED",
                    "message": "rescue channel failed unexpectedly",
                    "details": str(rescue_error),
                }],
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

if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "38575"))
    debug = os.environ.get("DEBUG", "false").lower() == "true"
    app.run(host=host, port=port, debug=debug, threaded=True)
