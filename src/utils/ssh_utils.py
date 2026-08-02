#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SSH 与远程命令。"""

from __future__ import annotations

import atexit
import io
from contextlib import AbstractContextManager
from typing import Optional

import paramiko

from src.utils.common_utils import q
from src.models import K8sTarget, SSHInfo, ServiceError
from src.utils.ssh_pool import SSHConnectionManager, SSHPoolConfig


class _SSHPhysicalClient:
    """实际持有 Paramiko SSHClient 的物理连接。"""

    def __init__(self, info: SSHInfo):
        self.info = info
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._connected = False

    def connect(self) -> "_SSHPhysicalClient":
        if self.is_active():
            return self

        connect_kwargs = {
            "hostname": self.info.host,
            "port": self.info.port,
            "username": self.info.username,
            "timeout": self.info.timeout,
            "banner_timeout": self.info.timeout,
            "auth_timeout": self.info.timeout,
        }
        if self.info.password:
            connect_kwargs.update(password=self.info.password, look_for_keys=False, allow_agent=False)
        elif self.info.private_key:
            connect_kwargs.update(
                pkey=self._load_private_key(self.info.private_key),
                look_for_keys=False,
                allow_agent=False,
            )
        elif self.info.private_key_path:
            connect_kwargs.update(
                key_filename=self.info.private_key_path,
                look_for_keys=False,
                allow_agent=False,
            )
        else:
            connect_kwargs.update(look_for_keys=True, allow_agent=True)

        self.client.connect(**connect_kwargs)
        self._connected = True
        return self

    def close(self) -> None:
        try:
            self.client.close()
        finally:
            self._connected = False

    def is_active(self) -> bool:
        if not self._connected:
            return False
        transport = self.client.get_transport()
        return bool(
            transport is not None
            and transport.is_active()
            and transport.is_authenticated()
        )

    @staticmethod
    def _load_private_key(private_key: str):
        errors = []
        key_classes = [paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey]
        dss_key = getattr(paramiko, "DSSKey", None)
        if dss_key is not None:
            key_classes.append(dss_key)

        for key_cls in key_classes:
            try:
                return key_cls.from_private_key(io.StringIO(private_key))
            except Exception as e:
                errors.append(str(e))
        raise ServiceError(
            "SSH_KEY_INVALID",
            f"invalid private key: {errors[-1] if errors else 'unknown'}",
        )

    @staticmethod
    def _decode_result(stdout, stderr, *, cmd: str, check: bool) -> tuple[str, str, int]:
        out_bytes = stdout.read()
        err_bytes = stderr.read()
        code = stdout.channel.recv_exit_status()
        out = out_bytes.decode("utf-8", errors="replace")
        err = err_bytes.decode("utf-8", errors="replace")
        if check and code != 0:
            raise ServiceError(
                "REMOTE_COMMAND_FAILED",
                f"remote command failed with exit code {code}",
                http_status=502,
                details={"cmd": cmd, "stderr": err[-4000:], "stdout": out[-4000:]},
            )
        return out, err, code

    def run(self, cmd: str, *, timeout: int = 300, check: bool = True) -> tuple[str, str, int]:
        stdin, stdout, stderr = self.client.exec_command(cmd, timeout=timeout)
        stdin.close()
        return self._decode_result(stdout, stderr, cmd=cmd, check=check)

    def run_with_input(
            self,
            cmd: str,
            input_data: bytes | str,
            *,
            timeout: int = 300,
            check: bool = True,
    ) -> tuple[str, str, int]:
        stdin, stdout, stderr = self.client.exec_command(cmd, timeout=timeout)
        payload = input_data.encode("utf-8") if isinstance(input_data, str) else input_data
        try:
            if payload:
                stdin.write(payload)
                stdin.flush()
        finally:
            stdin.channel.shutdown_write()
            stdin.close()
        return self._decode_result(stdout, stderr, cmd=cmd, check=check)

    def open_sftp(self):
        return self.client.open_sftp()


SSH_CONNECTION_MANAGER = SSHConnectionManager(
    client_factory=_SSHPhysicalClient,
    config=SSHPoolConfig.from_env(),
)
atexit.register(SSH_CONNECTION_MANAGER.close)


class SSHClientWrapper:
    """保持原调用接口的 SSH 连接租约门面。"""

    def __init__(self, info: SSHInfo):
        self.info = info
        self._lease: Optional[AbstractContextManager[_SSHPhysicalClient]] = None
        self._physical: Optional[_SSHPhysicalClient] = None

    def __enter__(self) -> "SSHClientWrapper":
        if self._physical is not None:
            raise ServiceError("SSH_LEASE_REENTERED", "ssh lease cannot be entered twice")

        lease = SSH_CONNECTION_MANAGER.acquire(self.info)
        self._lease = lease
        try:
            self._physical = lease.__enter__()
        except BaseException:
            self._lease = None
            self._physical = None
            raise
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> Optional[bool]:
        lease = self._lease
        self._lease = None
        self._physical = None
        if lease is None:
            return None
        return lease.__exit__(exc_type, exc_val, exc_tb)

    def close(self) -> None:
        self.__exit__(None, None, None)

    @property
    def client(self) -> paramiko.SSHClient:
        return self._require_physical().client

    def run(self, cmd: str, *, timeout: int = 300, check: bool = True) -> tuple[str, str, int]:
        return self._require_physical().run(cmd, timeout=timeout, check=check)

    def run_with_input(
            self,
            cmd: str,
            input_data: bytes | str,
            *,
            timeout: int = 300,
            check: bool = True,
    ) -> tuple[str, str, int]:
        return self._require_physical().run_with_input(
            cmd,
            input_data,
            timeout=timeout,
            check=check,
        )

    def open_sftp(self):
        return self._require_physical().open_sftp()

    def _require_physical(self) -> _SSHPhysicalClient:
        if self._physical is None:
            raise ServiceError(
                "SSH_LEASE_NOT_ACQUIRED",
                "SSHClientWrapper must be used inside a with block",
                http_status=500,
            )
        return self._physical


def kubectl_exec_cmd(
        target: K8sTarget,
        inner_cmd: str,
        container_user: Optional[str] = None,
        *,
        stdin: bool = False,
) -> str:
    user_part = f" --user={q(container_user)}" if container_user else ""
    stdin_part = " -i" if stdin else ""
    return (
        f"kubectl exec{stdin_part} -n {q(target.namespace)} {q(target.pod)} "
        f"-c {q(target.container)}{user_part} -- sh -c {q(inner_cmd)}"
    )
