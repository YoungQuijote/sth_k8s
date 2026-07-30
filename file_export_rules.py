#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""File export root registry and authorization."""

import os
from models import ServiceError

# 用户可见 root key 映射。实际部署建议通过环境变量/配置文件注入。
FILE_EXPORT_ROOTS = {
    "default": os.environ.get("K8S_FILE_EXPORT_ROOT", "/tmp/k8s-file-export"),
}

ROOT_DIR_TOKEN = os.environ.get("K8S_FILE_ROOT_TOKEN", "")
STORAGE_ROOT_TOKEN = os.environ.get("K8S_STORAGE_ROOT_TOKEN", "")


def resolve_root(root_key: str | None, root_dir: str | None, token: str | None) -> tuple[str, bool]:
    if root_dir:
        if token != ROOT_DIR_TOKEN:
            raise ServiceError("ROOT_DIR_AUTH_FAILED", "custom root_dir requires valid root token")
        return root_dir, True
    if root_key not in FILE_EXPORT_ROOTS:
        raise ServiceError("UNKNOWN_ROOT_KEY", f"unknown export root key: {root_key}")
    return FILE_EXPORT_ROOTS[root_key], False


def resolve_storage_root(default_root: str, custom_root: str | None, token: str | None) -> tuple[str, bool]:
    if custom_root:
        if token != STORAGE_ROOT_TOKEN:
            raise ServiceError("STORAGE_ROOT_AUTH_FAILED", "custom storage root requires valid storage token")
        return custom_root, True
    return default_root, False
