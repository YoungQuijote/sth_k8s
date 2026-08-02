#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Kubernetes 文件导出的受控根目录与高权限路径覆盖。"""

from __future__ import annotations

import hmac
import json
import os
import pathlib
import posixpath
from typing import Optional

from src.models import ServiceError

SOURCE_ROOTS_ENV = "K8S_FILE_SOURCE_ROOTS_JSON"
DEFAULT_SOURCE_ROOT_ENV = "K8S_FILE_SOURCE_ROOT"
DEFAULT_STORAGE_ROOT_ENV = "K8S_FILE_EXPORT_ROOT"
SOURCE_ADMIN_TOKEN_ENV = "K8S_FILE_SOURCE_ADMIN_TOKEN"
STORAGE_ADMIN_TOKEN_ENV = "K8S_FILE_STORAGE_ADMIN_TOKEN"


def _normalize_remote_root(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ServiceError("INVALID_REQUEST", f"{field_name} must be non-empty path")
    normalized = posixpath.normpath(value)
    if not normalized.startswith("/"):
        raise ServiceError("INVALID_REQUEST", f"{field_name} must be absolute path")
    return normalized


def _load_source_roots() -> dict[str, str]:
    roots: dict[str, str] = {}
    default_root = os.environ.get(DEFAULT_SOURCE_ROOT_ENV, "").strip()
    if default_root:
        roots["default"] = _normalize_remote_root(default_root, DEFAULT_SOURCE_ROOT_ENV)

    raw = os.environ.get(SOURCE_ROOTS_ENV, "").strip()
    if not raw:
        return roots
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"invalid {SOURCE_ROOTS_ENV}: {exc}") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError(f"{SOURCE_ROOTS_ENV} must be a JSON object")
    for key, value in parsed.items():
        if not isinstance(key, str) or not key or not isinstance(value, str):
            raise RuntimeError(f"{SOURCE_ROOTS_ENV} keys and values must be non-empty strings")
        roots[key] = _normalize_remote_root(value, f"{SOURCE_ROOTS_ENV}.{key}")
    return roots


FILE_EXPORT_ROOTS = _load_source_roots()
DEFAULT_STORAGE_ROOT = pathlib.Path(
    os.environ.get(DEFAULT_STORAGE_ROOT_ENV, "./tmp/k8s-file-exports")
).expanduser().resolve(strict=False)
SOURCE_ADMIN_TOKEN = os.environ.get(SOURCE_ADMIN_TOKEN_ENV, "")
STORAGE_ADMIN_TOKEN = os.environ.get(STORAGE_ADMIN_TOKEN_ENV, "")


def _require_token(configured: str, supplied: Optional[str], *, disabled_code: str, failed_code: str) -> None:
    if not configured:
        raise ServiceError(disabled_code, "this privileged path override is disabled")
    if not isinstance(supplied, str) or not hmac.compare_digest(configured, supplied):
        raise ServiceError(failed_code, "invalid authorization token")


def resolve_source_root(
    root_key: Optional[str],
    root_dir: Optional[str],
    auth_token: Optional[str],
) -> tuple[str, Optional[str], bool]:
    if root_dir is not None and root_key is not None:
        raise ServiceError("INVALID_REQUEST", "source.root_key and source.root_dir are mutually exclusive")
    if root_dir is not None:
        _require_token(
            SOURCE_ADMIN_TOKEN,
            auth_token,
            disabled_code="SOURCE_ROOT_OVERRIDE_DISABLED",
            failed_code="SOURCE_ROOT_AUTH_FAILED",
        )
        return _normalize_remote_root(root_dir, "source.root_dir"), None, True

    key = root_key or "default"
    root = FILE_EXPORT_ROOTS.get(key)
    if root is None:
        raise ServiceError(
            "UNKNOWN_SOURCE_ROOT_KEY",
            f"unknown source.root_key: {key}",
            details={"available_root_keys": sorted(FILE_EXPORT_ROOTS)},
        )
    return root, key, False


def resolve_storage_root(
    custom_root: Optional[str],
    auth_token: Optional[str],
) -> tuple[str, bool]:
    if custom_root is None:
        return str(DEFAULT_STORAGE_ROOT), False
    _require_token(
        STORAGE_ADMIN_TOKEN,
        auth_token,
        disabled_code="STORAGE_ROOT_OVERRIDE_DISABLED",
        failed_code="STORAGE_ROOT_AUTH_FAILED",
    )
    if not isinstance(custom_root, str) or not custom_root or "\x00" in custom_root:
        raise ServiceError("INVALID_REQUEST", "destination.storage_root must be non-empty path")
    path = pathlib.Path(custom_root).expanduser()
    if not path.is_absolute():
        raise ServiceError("INVALID_REQUEST", "destination.storage_root must be absolute path")
    return str(path.resolve(strict=False)), True
