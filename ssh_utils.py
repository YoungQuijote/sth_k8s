#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SSH 与远程命令"""

import io
from typing import Optional
import paramiko

from common_utils import q
from models import K8sTarget, SSHInfo, ServiceError

class SSHClientWrapper:
    def __init__(self, info: SSHInfo):
        self.info = info
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def __enter__(self) -> "SSHClientWrapper":
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
            connect_kwargs.update(pkey=self._load_private_key(self.info.private_key), look_for_keys=False, allow_agent=False)
        elif self.info.private_key_path:
            connect_kwargs.update(key_filename=self.info.private_key_path, look_for_keys=False, allow_agent=False)
        else:
            connect_kwargs.update(look_for_keys=True, allow_agent=True)
        self.client.connect(**connect_kwargs)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.client.close()

    @staticmethod
    def _load_private_key(private_key: str):
        errors = []
        for key_cls in (paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.DSSKey):
            try:
                return key_cls.from_private_key(io.StringIO(private_key))
            except Exception as e:
                errors.append(str(e))
        raise ServiceError("SSH_KEY_INVALID", f"invalid private key: {errors[-1] if errors else 'unknown'}")

    def run(self, cmd: str, *, timeout: int = 300, check: bool = True) -> tuple[str, str, int]:
        stdin, stdout, stderr = self.client.exec_command(cmd, timeout=timeout)
        del stdin
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

    def open_sftp(self):
        return self.client.open_sftp()

def kubectl_exec_cmd(target: K8sTarget, inner_cmd: str, container_user: Optional[str] = None) -> str:
    user_part = f" --user={q(container_user)}" if container_user else ""
    return (
        f"kubectl exec -n {q(target.namespace)} {q(target.pod)} "
        f"-c {q(target.container)}{user_part} -- sh -c {q(inner_cmd)}"
    )
