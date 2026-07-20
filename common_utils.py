#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""工具函数"""

import contextlib
import hashlib
import json
import os
import pathlib
import re as std_re
import shlex
import threading
import time
from typing import Any, Optional

from loguru import logger
from models import K8sTarget, SegmentRule, ServiceError, MODE_EXACT, MODE_CONTAINS, MODE_REGEX

try:
    import regex as safe_re  # type: ignore
    import stat as stat_mod
except Exception as e:  # pragma: no cover
    logger.debug(f"regex module unavailable: {e}")
    safe_re = None

_ZIP_CACHE_LOCKS: dict[str, threading.Lock] = {}
_ZIP_CACHE_LOCKS_GUARD = threading.Lock()

def get_zip_cache_lock(key: str) -> threading.Lock:
    with _ZIP_CACHE_LOCKS_GUARD:
        lock = _ZIP_CACHE_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _ZIP_CACHE_LOCKS[key] = lock
        return lock

def now_ts() -> float:
    return time.time()

def q(value: str) -> str:
    return shlex.quote(str(value))

def stable_json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def ensure_no_path_escape(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ServiceError("INVALID_REQUEST", f"{field_name} must be non-empty string")
    if "\x00" in value or "/" in value or "\\" in value:
        raise ServiceError("INVALID_REQUEST", f"{field_name} must be a single basename-like segment")
    if ".." in value:
        raise ServiceError("INVALID_REQUEST", f"{field_name} must not contain '..'")

def make_source_id(target: K8sTarget, base_path: str) -> str:
    payload = {
        "namespace": target.namespace,
        "pod": target.pod,
        "pod_uid": target.pod_uid or target.pod,
        "container": target.container,
        "base_path": base_path,
    }
    return sha256_text(stable_json(payload))[:16]

def safe_filename(name: str) -> str:
    name = name.replace("\x00", "_").replace("/", "_").replace("\\", "_")
    return name or "unnamed"

def compile_pattern(pattern: str, *, field_name: str):
    if not pattern or not isinstance(pattern, str):
        raise ServiceError("REGEX_COMPILE_FAILED", f"{field_name} must be non-empty regex")
    if len(pattern) > 4096:
        raise ServiceError("REGEX_COMPILE_FAILED", f"{field_name} is too long")
    try:
        return safe_re.compile(pattern) if safe_re is not None else std_re.compile(pattern)
    except Exception as e:
        raise ServiceError("REGEX_COMPILE_FAILED", f"compile {field_name} failed: {e}") from e

def regex_search(compiled: Any, text: str, timeout_ms: int) -> Optional[Any]:
    if safe_re is not None:
        try:
            return compiled.search(text, timeout=timeout_ms / 1000.0)
        except TimeoutError as e:
            raise ServiceError("REGEX_TIMEOUT", f"regex search timeout: {e}") from e
    return compiled.search(text)

def basename_match(name: str, rule: SegmentRule, timeout_ms: int) -> bool:
    if rule.mode == MODE_EXACT:
        return name == rule.value
    if rule.mode == MODE_CONTAINS:
        return rule.value in name
    if rule.mode == MODE_REGEX:
        return regex_search(compile_pattern(rule.value, field_name="basename regex"), name, timeout_ms) is not None
    raise ServiceError("INVALID_REQUEST", f"unsupported mode: {rule.mode}")

def extract_match_text(match: Any) -> str:
    return match.group(1) if getattr(match, "lastindex", None) else match.group(0)

def reverse_read_lines(path: pathlib.Path, block_size: int = 65536, encoding: str = "utf-8"):
    with path.open("rb") as f:
        f.seek(0, os.SEEK_END)
        position = f.tell()
        buffer = b""
        while position > 0:
            read_size = min(block_size, position)
            position -= read_size
            f.seek(position)
            chunk = f.read(read_size)
            buffer = chunk + buffer
            lines = buffer.split(b"\n")
            buffer = lines[0]
            for raw_line in reversed(lines[1:]):
                yield raw_line.decode(encoding, errors="replace")
        if buffer:
            yield buffer.decode(encoding, errors="replace")

def dir_size_bytes(path: pathlib.Path) -> int:
    total = 0
    if not path.exists():
        return total
    for root, _, files in os.walk(path):
        for file in files:
            with contextlib.suppress(OSError):
                total += (pathlib.Path(root) / file).stat().st_size
    return total

def atomic_write_json(path: pathlib.Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.parent / f".{path.name}.{os.getpid()}.{threading.get_ident()}.{time.time_ns()}.tmp"
    try:
        with tmp_path.open("w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        path.parent.mkdir(parents=True, exist_ok=True)
        os.replace(tmp_path, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            tmp_path.unlink()

def parse_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "y", "on")
    return default
