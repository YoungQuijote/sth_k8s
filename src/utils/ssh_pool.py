#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""单进程 SSH 连接池与连接准入控制。

边界：
- 每条连接同一时刻只租给一个请求。
- 相同目标的连接创建串行化，避免瞬时重复认证。
- 所有状态仅在当前 Python 进程内有效；当前应配合单 Gunicorn worker 使用。
"""

from __future__ import annotations

import hashlib
import os
import threading
import time
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Callable, Iterator, Optional, Protocol

import paramiko
from loguru import logger

from src.models import SSHInfo, ServiceError


class PoolClient(Protocol):
    def connect(self): ...
    def close(self) -> None: ...
    def is_active(self) -> bool: ...


def _env_int(name: str, default: int, minimum: int) -> int:
    try:
        value = int(os.environ.get(name, default))
    except (TypeError, ValueError):
        logger.warning("invalid {} value; use default {}", name, default)
        return default
    return value if value >= minimum else default


def _env_float(name: str, default: float, minimum: float) -> float:
    try:
        value = float(os.environ.get(name, default))
    except (TypeError, ValueError):
        logger.warning("invalid {} value; use default {}", name, default)
        return default
    return value if value >= minimum else default


@dataclass(frozen=True, slots=True)
class SSHPoolConfig:
    global_max_connections: int = 32
    target_max_connections: int = 4
    max_waiters: int = 100
    acquire_timeout_seconds: float = 30.0
    idle_timeout_seconds: float = 30.0
    max_lifetime_seconds: float = 600.0
    connect_failure_cooldown_seconds: float = 5.0
    reaper_interval_seconds: float = 5.0

    @classmethod
    def from_env(cls) -> "SSHPoolConfig":
        global_max = _env_int("SSH_POOL_GLOBAL_MAX_CONNECTIONS", 32, 1)
        target_max = min(_env_int("SSH_POOL_TARGET_MAX_CONNECTIONS", 4, 1), global_max)
        return cls(
            global_max_connections=global_max,
            target_max_connections=target_max,
            max_waiters=_env_int("SSH_POOL_MAX_WAITERS", 100, 0),
            acquire_timeout_seconds=_env_float("SSH_POOL_ACQUIRE_TIMEOUT_SECONDS", 30.0, 0.001),
            idle_timeout_seconds=_env_float("SSH_POOL_IDLE_TIMEOUT_SECONDS", 30.0, 0.0),
            max_lifetime_seconds=_env_float("SSH_POOL_MAX_LIFETIME_SECONDS", 600.0, 0.001),
            connect_failure_cooldown_seconds=_env_float("SSH_POOL_CONNECT_FAILURE_COOLDOWN_SECONDS", 5.0, 0.0),
            reaper_interval_seconds=_env_float("SSH_POOL_REAPER_INTERVAL_SECONDS", 5.0, 0.1),
        )


@dataclass(frozen=True, slots=True)
class SSHConnectionKey:
    host: str
    port: int
    username: str
    auth_type: str
    credential_digest: str

    @classmethod
    def from_info(cls, info: SSHInfo) -> "SSHConnectionKey":
        if info.password is not None:
            auth_type, credential = "password", info.password
        elif info.private_key is not None:
            auth_type, credential = "private_key", info.private_key
        elif info.private_key_path is not None:
            auth_type, credential = "private_key_path", info.private_key_path
        else:
            auth_type, credential = "agent", ""
        digest = hashlib.sha256(
            f"{auth_type}\0{credential}".encode("utf-8", errors="surrogatepass")
        ).hexdigest()
        return cls(info.host, info.port, info.username, auth_type, digest)

    def public_details(self) -> dict[str, object]:
        return {
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "auth_type": self.auth_type,
        }


@dataclass(slots=True)
class _Connection:
    client: PoolClient
    created_at: float
    last_used_at: float
    in_use: bool = True


@dataclass(slots=True)
class _TargetState:
    connections: list[_Connection] = field(default_factory=list)
    waiters: deque[object] = field(default_factory=deque)
    creating: bool = False
    failure_until: float = 0.0
    failure_code: Optional[str] = None
    failure_message: Optional[str] = None


class SSHConnectionManager:
    def __init__(self, client_factory: Callable[[SSHInfo], PoolClient], config: Optional[SSHPoolConfig] = None):
        self.config = config or SSHPoolConfig.from_env()
        self._client_factory = client_factory
        self._condition = threading.Condition(threading.RLock())
        self._states: dict[SSHConnectionKey, _TargetState] = {}
        self._total_connections = 0  # 已连接 + 正在创建且已预留的名额
        self._total_waiters = 0
        self._closed = False
        self._stop = threading.Event()
        self._reaper: Optional[threading.Thread] = None

    @contextmanager
    def acquire(self, info: SSHInfo, timeout: Optional[float] = None) -> Iterator[PoolClient]:
        key = SSHConnectionKey.from_info(info)
        record = self._acquire_record(
            info,
            key,
            self.config.acquire_timeout_seconds if timeout is None else float(timeout),
        )
        invalidate = False
        try:
            yield record.client
        except BaseException as exc:
            invalidate = self._is_connection_error(exc)
            raise
        finally:
            self._release(key, record, invalidate)

    def _acquire_record(self, info: SSHInfo, key: SSHConnectionKey, timeout: float) -> _Connection:
        if timeout <= 0:
            raise ServiceError("SSH_POOL_ACQUIRE_TIMEOUT", "ssh acquire timeout must be greater than 0", http_status=503)

        deadline = time.monotonic() + timeout
        ticket: Optional[object] = None
        while True:
            create = False
            with self._condition:
                if self._closed:
                    self._drop_waiter(key, ticket)
                    raise ServiceError("SSH_POOL_CLOSED", "ssh connection pool is closed", http_status=503)

                self._start_reaper()
                state = self._states.setdefault(key, _TargetState())
                now = time.monotonic()
                self._prune(state, now)

                is_turn = ticket is None and not state.waiters
                if ticket is not None:
                    is_turn = bool(state.waiters and state.waiters[0] is ticket)

                if is_turn:
                    record = self._take_idle(state, now)
                    if record is not None:
                        self._drop_waiter(key, ticket)
                        return record

                    if state.failure_until > now:
                        self._drop_waiter(key, ticket)
                        raise ServiceError(
                            state.failure_code or "SSH_CONNECT_FAILED",
                            state.failure_message or "recent ssh connection attempt failed",
                            http_status=502,
                            details={
                                "failure_cooldown_remaining": round(state.failure_until - now, 3),
                                **key.public_details(),
                            },
                        )

                    target_count = len(state.connections) + int(state.creating)
                    if not state.creating and target_count < self.config.target_max_connections:
                        if self._total_connections >= self.config.global_max_connections:
                            self._evict_oldest_idle(exclude_key=key)
                        if self._total_connections < self.config.global_max_connections:
                            state.creating = True
                            self._total_connections += 1
                            self._drop_waiter(key, ticket)
                            ticket = None
                            create = True

                if not create:
                    if ticket is None:
                        if self._total_waiters >= self.config.max_waiters:
                            raise ServiceError(
                                "SSH_POOL_QUEUE_FULL",
                                "ssh connection wait queue is full",
                                http_status=503,
                                details={"max_waiters": self.config.max_waiters, **key.public_details()},
                            )
                        ticket = object()
                        state.waiters.append(ticket)
                        self._total_waiters += 1

                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        self._drop_waiter(key, ticket)
                        raise ServiceError(
                            "SSH_POOL_ACQUIRE_TIMEOUT",
                            "timed out waiting for an available ssh connection",
                            http_status=503,
                            details={"timeout_seconds": timeout, **key.public_details()},
                        )
                    self._condition.wait(remaining)
                    continue

            if create:
                return self._create(info, key)

    def _create(self, info: SSHInfo, key: SSHConnectionKey) -> _Connection:
        client = self._client_factory(info)
        try:
            client.connect()
        except BaseException as exc:
            error = self._normalize_connect_error(exc)
            with self._condition:
                state = self._states.setdefault(key, _TargetState())
                state.creating = False
                self._total_connections = max(0, self._total_connections - 1)
                state.failure_code = error.code
                state.failure_message = error.message
                state.failure_until = time.monotonic() + self.config.connect_failure_cooldown_seconds
                self._condition.notify_all()
            try:
                client.close()
            except Exception:
                logger.exception("failed to close unsuccessful ssh client")
            raise error from exc

        now = time.monotonic()
        record = _Connection(client, now, now, True)
        with self._condition:
            state = self._states.setdefault(key, _TargetState())
            state.creating = False
            state.failure_until = 0.0
            state.failure_code = None
            state.failure_message = None
            state.connections.append(record)
            self._condition.notify_all()
        return record

    def _release(self, key: SSHConnectionKey, record: _Connection, invalidate: bool) -> None:
        close = False
        with self._condition:
            state = self._states.get(key)
            if state is None or record not in state.connections:
                close = True
            else:
                now = time.monotonic()
                expired = now - record.created_at >= self.config.max_lifetime_seconds
                if self._closed or invalidate or expired or not record.client.is_active():
                    state.connections.remove(record)
                    self._total_connections = max(0, self._total_connections - 1)
                    close = True
                else:
                    record.in_use = False
                    record.last_used_at = now
                self._condition.notify_all()
        if close:
            try:
                record.client.close()
            except Exception:
                logger.exception("failed to close pooled ssh client")

    def _take_idle(self, state: _TargetState, now: float) -> Optional[_Connection]:
        for record in state.connections:
            if not record.in_use and self._usable(record, now):
                record.in_use = True
                record.last_used_at = now
                return record
        return None

    def _usable(self, record: _Connection, now: float) -> bool:
        return (
            now - record.created_at < self.config.max_lifetime_seconds
            and now - record.last_used_at < self.config.idle_timeout_seconds
            and record.client.is_active()
        )

    def _prune(self, state: _TargetState, now: float) -> None:
        stale = [r for r in state.connections if not r.in_use and not self._usable(r, now)]
        for record in stale:
            state.connections.remove(record)
            self._total_connections = max(0, self._total_connections - 1)
            try:
                record.client.close()
            except Exception:
                logger.exception("failed to close stale ssh client")

    def _evict_oldest_idle(self, exclude_key: SSHConnectionKey) -> bool:
        candidate = None
        candidate_state = None
        for key, state in self._states.items():
            if key == exclude_key:
                continue
            for record in state.connections:
                if record.in_use:
                    continue
                if candidate is None or record.last_used_at < candidate.last_used_at:
                    candidate, candidate_state = record, state
        if candidate is None or candidate_state is None:
            return False
        candidate_state.connections.remove(candidate)
        self._total_connections = max(0, self._total_connections - 1)
        try:
            candidate.client.close()
        except Exception:
            logger.exception("failed to close evicted ssh client")
        return True

    def _drop_waiter(self, key: SSHConnectionKey, ticket: Optional[object]) -> None:
        if ticket is None:
            return
        state = self._states.get(key)
        if state is not None:
            try:
                state.waiters.remove(ticket)
            except ValueError:
                pass
        self._total_waiters = max(0, self._total_waiters - 1)
        self._condition.notify_all()

    def _start_reaper(self) -> None:
        if self._reaper is not None and self._reaper.is_alive():
            return
        self._stop.clear()
        self._reaper = threading.Thread(target=self._reaper_loop, name="ssh-pool-reaper", daemon=True)
        self._reaper.start()

    def _reaper_loop(self) -> None:
        while not self._stop.wait(self.config.reaper_interval_seconds):
            with self._condition:
                if self._closed:
                    return
                now = time.monotonic()
                for state in self._states.values():
                    self._prune(state, now)
                self._condition.notify_all()

    def snapshot(self) -> dict[str, object]:
        with self._condition:
            targets = []
            in_use = idle = creating = 0
            for key, state in self._states.items():
                target_in_use = sum(1 for r in state.connections if r.in_use)
                target_idle = len(state.connections) - target_in_use
                in_use += target_in_use
                idle += target_idle
                creating += int(state.creating)
                targets.append({
                    **key.public_details(),
                    "connections": len(state.connections),
                    "in_use": target_in_use,
                    "idle": target_idle,
                    "creating": state.creating,
                    "waiters": len(state.waiters),
                })
            return {
                "mode": "single_process",
                "global_max_connections": self.config.global_max_connections,
                "target_max_connections": self.config.target_max_connections,
                "max_waiters": self.config.max_waiters,
                "acquire_timeout_seconds": self.config.acquire_timeout_seconds,
                "idle_timeout_seconds": self.config.idle_timeout_seconds,
                "max_lifetime_seconds": self.config.max_lifetime_seconds,
                "total_connections": self._total_connections,
                "in_use_connections": in_use,
                "idle_connections": idle,
                "creating_connections": creating,
                "waiters": self._total_waiters,
                "targets": targets,
            }

    def close(self) -> None:
        clients = []
        with self._condition:
            if self._closed:
                return
            self._closed = True
            self._stop.set()
            for state in self._states.values():
                clients.extend(record.client for record in state.connections)
                state.connections.clear()
                state.waiters.clear()
                state.creating = False
            self._states.clear()
            self._total_connections = 0
            self._total_waiters = 0
            self._condition.notify_all()
        for client in clients:
            try:
                client.close()
            except Exception:
                logger.exception("failed to close ssh client while shutting down pool")

    @staticmethod
    def _normalize_connect_error(exc: BaseException) -> ServiceError:
        if isinstance(exc, paramiko.AuthenticationException):
            return ServiceError("SSH_AUTH_FAILED", f"ssh auth failed: {exc}", http_status=502)
        if isinstance(exc, ServiceError):
            return exc
        return ServiceError("SSH_CONNECT_FAILED", f"ssh failed: {exc}", http_status=502)

    @staticmethod
    def _is_connection_error(exc: BaseException) -> bool:
        if isinstance(exc, (paramiko.SSHException, OSError, EOFError)):
            return True
        return isinstance(exc, ServiceError) and exc.code in {"SSH_CONNECT_FAILED", "SSH_AUTH_FAILED"}
