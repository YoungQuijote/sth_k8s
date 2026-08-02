#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GZIP 日志安全解压、解压缓存与远端实时尾读。"""

from __future__ import annotations

import contextlib
import gzip
import json
import os
import pathlib
import shutil
import threading
import time
from typing import Optional

from src.models import K8sTarget, Options, RemoteLogFile, ServiceError, WarningItem
from src.utils.common_utils import atomic_write_json, dir_size_bytes, now_ts, q, sha256_text, stable_json
from src.utils.ssh_utils import SSHClientWrapper, kubectl_exec_cmd

_GZIP_MAGIC = b"\x1f\x8b"
_GZIP_CACHE_LOCKS: dict[str, threading.Lock] = {}
_GZIP_CACHE_LOCKS_GUARD = threading.Lock()

# argv[1]: gzip 文件；argv[2]: 解压后保留的尾部字节；argv[3]: 最大解压字节。
# GZIP 是单数据流，不落完整临时文件；只在内存中保留解压后的尾部窗口。
REAL_TIME_GZIP_TAIL_SCRIPT = r'''
import collections
import gzip
import sys

path = sys.argv[1]
tail_bytes = int(sys.argv[2])
max_uncompressed = int(sys.argv[3])
chunks = collections.deque()
retained = 0
total = 0

try:
    with gzip.open(path, "rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if max_uncompressed > 0 and total > max_uncompressed:
                sys.stderr.write("gzip uncompressed size exceeded limit")
                raise SystemExit(13)
            chunks.append(chunk)
            retained += len(chunk)
            while chunks and retained - len(chunks[0]) >= tail_bytes:
                retained -= len(chunks.popleft())
            if chunks and retained > tail_bytes:
                trim = retained - tail_bytes
                chunks[0] = chunks[0][trim:]
                retained -= trim
except (gzip.BadGzipFile, EOFError, OSError) as exc:
    sys.stderr.write("invalid gzip stream: " + str(exc))
    raise SystemExit(14)

sys.stdout.buffer.write(b"".join(chunks))
'''


def is_tar_gzip_name(name: str) -> bool:
    lower = name.lower()
    return lower.endswith((".tar.gz", ".tgz", ".tar.gzip"))


def is_gzip_log_file(file: RemoteLogFile) -> bool:
    """按远端文件名识别单文件 GZIP；远端实时模式无法预读 magic。"""
    return file.name.lower().endswith((".gz", ".gzip", ".tgz"))


def is_gzip_path(path: pathlib.Path) -> bool:
    """按 magic number 识别本地 GZIP，避免只信扩展名。"""
    try:
        with path.open("rb") as stream:
            return stream.read(2) == _GZIP_MAGIC
    except OSError:
        return False


def _cache_lock(key: str) -> threading.Lock:
    with _GZIP_CACHE_LOCKS_GUARD:
        lock = _GZIP_CACHE_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _GZIP_CACHE_LOCKS[key] = lock
        return lock


def _cache_entry_dir_for_local_file(path: pathlib.Path) -> pathlib.Path:
    resolved = path.resolve()
    for parent in resolved.parents:
        if parent.name == "files":
            return parent.parent
    return resolved.parent


def _fingerprint(path: pathlib.Path) -> str:
    st = path.stat()
    return sha256_text(stable_json({
        "archive_type": "gzip",
        "path": str(path.resolve()),
        "size": st.st_size,
        "mtime_ns": st.st_mtime_ns,
    }))


def _output_name(path: pathlib.Path) -> str:
    name = path.name
    lower = name.lower()
    if lower.endswith(".gzip"):
        name = name[:-5]
    elif lower.endswith(".gz"):
        name = name[:-3]
    return name or "decompressed.log"


def _meta_path(extract_dir: pathlib.Path) -> pathlib.Path:
    return extract_dir / ".meta.json"


def _read_last_used(extract_dir: pathlib.Path) -> float:
    try:
        with _meta_path(extract_dir).open("r", encoding="utf-8") as stream:
            return float((json.load(stream) or {}).get("last_used_at") or 0.0)
    except Exception:
        return 0.0


def _write_meta(extract_dir: pathlib.Path, gzip_path: pathlib.Path) -> None:
    meta_path = _meta_path(extract_dir)
    meta = {
        "archive_type": "gzip",
        "archive_path": str(gzip_path.resolve()),
        "last_used_at": now_ts(),
        "updated_at": now_ts(),
    }
    if meta_path.exists():
        with contextlib.suppress(Exception):
            with meta_path.open("r", encoding="utf-8") as stream:
                old = json.load(stream)
            meta["created_at"] = old.get("created_at") or old.get("updated_at") or now_ts()
    meta.setdefault("created_at", now_ts())
    atomic_write_json(meta_path, meta)


def _try_write_meta(extract_dir: pathlib.Path, gzip_path: pathlib.Path, warnings: list[WarningItem]) -> None:
    try:
        _write_meta(extract_dir, gzip_path)
    except FileNotFoundError as exc:
        warnings.append(WarningItem(
            "GZIP_CACHE_META_UPDATE_RACE",
            "gzip cache metadata update skipped because concurrent request changed temp file",
            file=str(gzip_path),
            details=str(exc),
        ))
    except Exception as exc:
        warnings.append(WarningItem(
            "GZIP_CACHE_META_UPDATE_FAILED",
            f"gzip cache metadata update failed: {exc}",
            file=str(gzip_path),
        ))


def _gc_extract_cache(root: pathlib.Path, options: Options, warnings: list[WarningItem]) -> None:
    if not root.exists():
        return
    try:
        now = now_ts()
        ttl = max(0, options.zip_extract_cache_ttl_seconds)
        dirs = [path for path in root.iterdir() if path.is_dir() and ".part-" not in path.name]
        for path in dirs:
            last_used = _read_last_used(path)
            if ttl and last_used and now - last_used > ttl:
                shutil.rmtree(path, ignore_errors=True)

        max_size = options.zip_extract_cache_max_size_mb * 1024 * 1024
        total = dir_size_bytes(root)
        if max_size > 0 and total > max_size:
            dirs = [path for path in root.iterdir() if path.is_dir() and ".part-" not in path.name]
            dirs.sort(key=_read_last_used)
            for path in dirs:
                if total <= max_size:
                    break
                size = dir_size_bytes(path)
                shutil.rmtree(path, ignore_errors=True)
                total -= size
    except Exception as exc:
        warnings.append(WarningItem("GZIP_CACHE_GC_FAILED", f"gzip extract cache gc failed: {exc}"))


def safe_extract_gzip(
    gzip_path: pathlib.Path,
    dest_dir: pathlib.Path,
    options: Options,
    warnings: list[WarningItem],
) -> Optional[pathlib.Path]:
    """安全解压单个 GZIP 数据流，并强制限制解压后大小。"""
    if is_tar_gzip_name(gzip_path.name):
        warnings.append(WarningItem(
            "GZIP_TAR_ARCHIVE_NOT_SUPPORTED",
            "tar.gz/tgz is not a single-file gzip log; skip archive",
            file=str(gzip_path),
        ))
        return None
    max_total = options.max_zip_uncompressed_size_mb * 1024 * 1024
    target = dest_dir / _output_name(gzip_path)
    total = 0
    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
        with gzip.open(gzip_path, "rb") as src, target.open("wb") as dst:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if max_total > 0 and total > max_total:
                    warnings.append(WarningItem(
                        "GZIP_TOO_LARGE",
                        "gzip uncompressed size exceeded max_zip_uncompressed_size_mb; skip gzip",
                        file=str(gzip_path),
                        details={"limit_bytes": max_total, "observed_bytes": total},
                    ))
                    return None
                dst.write(chunk)
        return target
    except (gzip.BadGzipFile, EOFError, OSError) as exc:
        target.unlink(missing_ok=True)
        warnings.append(WarningItem(
            "GZIP_DECOMPRESS_FAILED",
            f"gzip decompress failed: {exc}",
            file=str(gzip_path),
        ))
        return None
    finally:
        if total > max_total > 0:
            target.unlink(missing_ok=True)


def get_cached_gzip_extract(
    gzip_path: pathlib.Path,
    options: Options,
    warnings: list[WarningItem],
) -> list[pathlib.Path]:
    """按 path+size+mtime 指纹复用解压结果，缓存参数沿用 ZIP 解压缓存配置。"""
    entry_dir = _cache_entry_dir_for_local_file(gzip_path)
    root = entry_dir / "zip_extract"  # 与 ZIP 共用解压缓存配额
    root.mkdir(parents=True, exist_ok=True)
    _gc_extract_cache(root, options, warnings)
    fingerprint = _fingerprint(gzip_path)

    with _cache_lock(fingerprint):
        extract_dir = root / fingerprint
        meta_path = _meta_path(extract_dir)
        if extract_dir.is_dir() and meta_path.is_file():
            files = [path for path in extract_dir.iterdir() if path.is_file() and path.name != ".meta.json"]
            if files:
                _try_write_meta(extract_dir, gzip_path, warnings)
                return sorted(files, key=lambda path: path.name, reverse=True)

        staging = root / f"{fingerprint}.part-{os.getpid()}-{threading.get_ident()}-{time.time_ns()}"
        shutil.rmtree(staging, ignore_errors=True)
        staging.mkdir(parents=True, exist_ok=True)
        extracted = safe_extract_gzip(gzip_path, staging, options, warnings)
        if extracted is None:
            shutil.rmtree(staging, ignore_errors=True)
            return []
        _try_write_meta(staging, gzip_path, warnings)
        if extract_dir.exists():
            shutil.rmtree(extract_dir, ignore_errors=True)
        os.replace(staging, extract_dir)
        return [extract_dir / extracted.name]


def read_remote_gzip_tail_text(
    ssh: SSHClientWrapper,
    target: K8sTarget,
    file: RemoteLogFile,
    options: Options,
) -> str:
    """在容器内流式解压 GZIP，只返回解压后尾部窗口。"""
    if is_tar_gzip_name(file.name):
        raise ServiceError(
            "REAL_TIME_GZIP_TAR_ARCHIVE_NOT_SUPPORTED",
            "tar.gz/tgz is not supported as a single-file gzip log",
            http_status=400,
            details={"remote_path": file.remote_path},
        )
    max_total = options.max_zip_uncompressed_size_mb * 1024 * 1024
    inner = (
        f"python3 -c {q(REAL_TIME_GZIP_TAIL_SCRIPT)} {q(file.remote_path)} "
        f"{int(options.real_tail_bytes)} {int(max_total)}"
    )
    cmd = kubectl_exec_cmd(target, inner, options.container_user)
    out, err, code = ssh.run(cmd, timeout=options.remote_cmd_timeout, check=False)
    if code == 0:
        return out
    if code == 13:
        raise ServiceError(
            "REAL_TIME_GZIP_TOO_LARGE",
            "gzip uncompressed size exceeded max_zip_uncompressed_size_mb",
            http_status=413,
            details={"stderr": err[-4000:], "remote_path": file.remote_path, "limit_bytes": max_total},
        )
    if code == 14:
        raise ServiceError(
            "REAL_TIME_GZIP_INVALID",
            "invalid or truncated gzip stream",
            http_status=502,
            details={"stderr": err[-4000:], "remote_path": file.remote_path},
        )
    lower_err = err.lower()
    if "python3: not found" in lower_err or "python: not found" in lower_err or code == 127:
        raise ServiceError(
            "REAL_TIME_GZIP_READER_NOT_AVAILABLE",
            "python3 is not available in container, cannot inspect gzip in real_time mode",
            http_status=502,
            details=err[-4000:],
        )
    raise ServiceError(
        "REAL_TIME_GZIP_TAIL_FAILED",
        f"real_time gzip tail failed for pod {target.pod}",
        http_status=502,
        details={"stderr": err[-4000:], "remote_path": file.remote_path, "exit_code": code},
    )
