#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Kubernetes file export orchestration.

This module intentionally keeps export lifecycle independent from log cache.
"""

from __future__ import annotations

import hashlib
import pathlib
import shutil

from models import ServiceError
from file_export_models import OVERWRITE_REJECT, FileExportRequest


def build_export_identity(target, relative_dir: str) -> str:
    payload = f"{target.namespace}|{target.pod_uid or target.pod}|{target.container}|{relative_dir}"
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def prepare_export_dir(req: FileExportRequest, target) -> pathlib.Path:
    path = pathlib.Path(req.storage_root) / req.relative_dir / build_export_identity(target, req.relative_dir)
    if path.exists() and req.overwrite_policy == OVERWRITE_REJECT:
        raise ServiceError("EXPORT_TARGET_EXISTS", "export target already exists")
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def export_files(req: FileExportRequest, files: list[pathlib.Path], target) -> pathlib.Path:
    output = prepare_export_dir(req, target)
    for src in files:
        shutil.copy2(src, output / src.name)
    return output
