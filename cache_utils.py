#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""缓存"""

import contextlib
import dataclasses
import json
import pathlib
import shutil
import threading
from typing import Any, Optional

from models import ExtractRequest, LocalLogFile, Options, RemoteLogFile, ResolvedLogBatch, WarningItem, DEFAULT_CACHE_ROOT
from common_utils import atomic_write_json, dir_size_bytes, now_ts, sha256_text, stable_json

class CacheStore:
    def __init__(self, root: str):
        self.root = pathlib.Path(root)
        self.index_path = self.root / "index.json"
        self.objects_dir = self.root / "objects"
        self._lock = threading.RLock()
        self._key_locks: dict[str, threading.Lock] = {}
        self._last_gc = 0.0
        self.root.mkdir(parents=True, exist_ok=True)
        self.objects_dir.mkdir(parents=True, exist_ok=True)

    def _load_index_unlocked(self) -> dict[str, Any]:
        if not self.index_path.exists():
            return {"entries": {}}
        try:
            with self.index_path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict) or not isinstance(data.get("entries"), dict):
                return {"entries": {}}
            return data
        except Exception:
            return {"entries": {}}

    def _save_index_unlocked(self, data: dict[str, Any]) -> None:
        atomic_write_json(self.index_path, data)

    def get(self, cache_key: str) -> Optional[dict[str, Any]]:
        with self._lock:
            index = self._load_index_unlocked()
            entry = index.get("entries", {}).get(cache_key)
            if entry:
                entry["last_used_at"] = now_ts()
                index["entries"][cache_key] = entry
                self._save_index_unlocked(index)
            return entry

    def set(self, cache_key: str, entry: dict[str, Any]) -> None:
        with self._lock:
            index = self._load_index_unlocked()
            entry["last_used_at"] = now_ts()
            index.setdefault("entries", {})[cache_key] = entry
            self._save_index_unlocked(index)

    def key_lock(self, cache_key: str) -> threading.Lock:
        with self._lock:
            lock = self._key_locks.get(cache_key)
            if lock is None:
                lock = threading.Lock()
                self._key_locks[cache_key] = lock
            return lock

    def cache_dir(self, cache_key: str) -> pathlib.Path:
        return self.objects_dir / cache_key[:2] / cache_key[2:4] / cache_key

    def gc_if_needed(self, options: Options, warnings: list[WarningItem]) -> None:
        if now_ts() - self._last_gc < options.cache_gc_interval_seconds:
            return
        self._last_gc = now_ts()
        try:
            self.gc(options)
        except Exception as e:
            warnings.append(WarningItem("CACHE_GC_FAILED", f"cache gc failed: {e}"))

    def gc(self, options: Options) -> None:
        with self._lock:
            index = self._load_index_unlocked()
            entries = index.setdefault("entries", {})
            now = now_ts()
            for key, entry in list(entries.items()):
                last_used = float(entry.get("last_used_at") or 0)
                if now - last_used > options.cache_max_age_seconds:
                    shutil.rmtree(self.cache_dir(key), ignore_errors=True)
                    entries.pop(key, None)
            max_size = options.cache_max_size_mb * 1024 * 1024
            total_size = dir_size_bytes(self.objects_dir)
            if total_size > max_size:
                ordered = sorted(entries.items(), key=lambda kv: float(kv[1].get("last_used_at") or 0))
                for key, _ in ordered:
                    if total_size <= max_size:
                        break
                    cdir = self.cache_dir(key)
                    size = dir_size_bytes(cdir)
                    shutil.rmtree(cdir, ignore_errors=True)
                    entries.pop(key, None)
                    total_size -= size
            self._save_index_unlocked(index)

CACHE = CacheStore(DEFAULT_CACHE_ROOT)

def build_cache_key(req: ExtractRequest) -> str:
    payload = {
        "node_ip": req.ssh.host,
        "node_port": req.ssh.port,
        "node_user": req.ssh.username,
        "selector": dataclasses.asdict(req.selector),
        "container_user": req.options.container_user,
        "pod_match_policy": req.options.pod_match_policy,
        "path_segments": [dataclasses.asdict(s) for s in req.path_segments],
        "log_file": dataclasses.asdict(req.log_file),
        "path_match_policy": "search_mtime_desc_name_desc_limit_1",
        "log_match_policy": "search_mtime_desc_name_desc_all",
    }
    return sha256_text(stable_json(payload))

def cache_files_exist(entry: Optional[dict[str, Any]]) -> bool:
    if not entry:
        return False
    files = entry.get("files") or []
    return bool(files) and all(pathlib.Path(f.get("local_path", "")).is_file() for f in files)

def entry_to_local_files(entry: dict[str, Any]) -> list[LocalLogFile]:
    result = [LocalLogFile(
        local_path=f["local_path"], remote_path=f.get("remote_path", ""),
        name=f.get("name") or pathlib.Path(f["local_path"]).name,
        mtime=float(f.get("mtime") or 0), size=int(f.get("size") or 0),
        source_id=f.get("source_id", ""), namespace=f.get("namespace", ""),
        pod=f.get("pod", ""), pod_uid=f.get("pod_uid"), container=f.get("container", ""),
        container_id=f.get("container_id"),
    ) for f in entry.get("files") or []]
    result.sort(key=lambda x: (x.mtime, x.pod, x.name), reverse=True)
    return result

def remote_signature(files: list[RemoteLogFile]) -> list[tuple[str, str, str, str, float, int]]:
    return sorted((f.source_id, f.pod_uid or f.pod, f.container, f.remote_path, float(f.mtime), int(f.size)) for f in files)

def flatten_batches(batches: list[ResolvedLogBatch]) -> list[RemoteLogFile]:
    result: list[RemoteLogFile] = []
    for batch in batches:
        result.extend(batch.remote_files)
    return result

def remote_batches_signature(batches: list[ResolvedLogBatch]) -> list[tuple[str, str, str, str, float, int]]:
    return remote_signature(flatten_batches(batches))

def cached_signature(entry: Optional[dict[str, Any]]) -> list[tuple[str, str, str, str, float, int]]:
    if not entry:
        return []
    return sorted((f.get("source_id", ""), f.get("pod_uid") or f.get("pod", ""), f.get("container", ""), f.get("remote_path", ""), float(f.get("mtime") or 0), int(f.get("size") or 0)) for f in entry.get("files") or [])

def cache_entry_fingerprint(entry: Optional[dict[str, Any]]) -> str:
    if not entry:
        return ""
    payload = [{"local_path": f.get("local_path", ""), "source_id": f.get("source_id", ""), "remote_path": f.get("remote_path", ""), "mtime": f.get("mtime"), "size": f.get("size")} for f in entry.get("files") or []]
    return sha256_text(stable_json(payload))

def cache_last_refresh_ts(entry: Optional[dict[str, Any]]) -> float:
    if not entry:
        return 0.0
    candidates = [entry.get("updated_at"), entry.get("created_at")]
    candidates.extend(f.get("fetched_at") for f in entry.get("files") or [])
    best = 0.0
    for value in candidates:
        with contextlib.suppress(TypeError, ValueError):
            best = max(best, float(value or 0))
    return best

def cache_refresh_interval_remaining(entry: Optional[dict[str, Any]], options: Options) -> float:
    if not entry or options.refresh_interval <= 0:
        return 0.0
    last_refresh = cache_last_refresh_ts(entry)
    if last_refresh <= 0:
        return 0.0
    remaining = float(options.refresh_interval) - (now_ts() - last_refresh)
    return remaining if remaining > 0 else 0.0

def should_skip_refresh_by_interval(entry: Optional[dict[str, Any]], options: Options) -> bool:
    return cache_refresh_interval_remaining(entry, options) > 0
