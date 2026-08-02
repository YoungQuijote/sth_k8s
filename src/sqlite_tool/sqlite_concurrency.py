#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""单进程 SQLite 数据源查询准入控制。"""

from __future__ import annotations

import contextlib
import os
import threading
from dataclasses import dataclass
from typing import Iterator

from src.models import ServiceError


@dataclass(frozen=True)
class SQLiteConcurrencyConfig:
    max_per_source: int = 2
    max_waiters: int = 100
    acquire_timeout_seconds: float = 30.0

    @classmethod
    def from_env(cls) -> "SQLiteConcurrencyConfig":
        return cls(
            max_per_source=max(1, int(os.environ.get("SQLITE_SOURCE_MAX_CONCURRENCY", "2"))),
            max_waiters=max(0, int(os.environ.get("SQLITE_SOURCE_MAX_WAITERS", "100"))),
            acquire_timeout_seconds=max(
                0.0,
                float(os.environ.get("SQLITE_SOURCE_ACQUIRE_TIMEOUT_SECONDS", "30")),
            ),
        )


class SQLiteSourceLimiter:
    def __init__(self, config: SQLiteConcurrencyConfig):
        self.config = config
        self._guard = threading.Lock()
        self._semaphores: dict[str, threading.BoundedSemaphore] = {}
        self._waiters = 0

    def _get_semaphore(self, key: str) -> threading.BoundedSemaphore:
        with self._guard:
            semaphore = self._semaphores.get(key)
            if semaphore is None:
                semaphore = threading.BoundedSemaphore(self.config.max_per_source)
                self._semaphores[key] = semaphore
            return semaphore

    @contextlib.contextmanager
    def acquire(self, key: str) -> Iterator[None]:
        semaphore = self._get_semaphore(key)
        if semaphore.acquire(blocking=False):
            try:
                yield
            finally:
                semaphore.release()
            return

        with self._guard:
            if self._waiters >= self.config.max_waiters:
                raise ServiceError(
                    "SQLITE_SOURCE_QUEUE_FULL",
                    "sqlite source query wait queue is full",
                    http_status=503,
                    details={"max_waiters": self.config.max_waiters},
                )
            self._waiters += 1

        try:
            acquired = semaphore.acquire(timeout=self.config.acquire_timeout_seconds)
        finally:
            with self._guard:
                self._waiters -= 1

        if not acquired:
            raise ServiceError(
                "SQLITE_SOURCE_ACQUIRE_TIMEOUT",
                "timed out waiting for sqlite source query slot",
                http_status=503,
                details={"timeout_seconds": self.config.acquire_timeout_seconds},
            )
        try:
            yield
        finally:
            semaphore.release()


SQLITE_SOURCE_LIMITER = SQLiteSourceLimiter(SQLiteConcurrencyConfig.from_env())
