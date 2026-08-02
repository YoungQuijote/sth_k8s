#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""日志拉取"""

import os
import pathlib
import shutil
import tarfile
import time
from typing import Any

import paramiko

from src.models import K8sTarget, Options, RemoteLogFile, ResolvedLogBatch, ServiceError, WarningItem
from src.models import DEFAULT_CACHE_ROOT, DEFAULT_REMOTE_TMP_PREFIX, POD_MATCH_ALL, TRANSFER_COMPATIBLE, TRANSFER_STREAM
from src.utils.common_utils import q, stat_mod, stable_json, sha256_text
from src.utils.cache_utils import CacheStore
from src.utils.ssh_utils import SSHClientWrapper

CACHE = CacheStore(DEFAULT_CACHE_ROOT)

def download_sftp_dir(sftp: paramiko.SFTPClient, remote_dir: str, local_dir: pathlib.Path) -> None:
    local_dir.mkdir(parents=True, exist_ok=True)
    for attr in sftp.listdir_attr(remote_dir):
        rpath = remote_dir.rstrip("/") + "/" + attr.filename
        lpath = local_dir / attr.filename
        if stat_mod.S_ISDIR(attr.st_mode):
            download_sftp_dir(sftp, rpath, lpath)
        elif stat_mod.S_ISREG(attr.st_mode):
            sftp.get(rpath, str(lpath))

def make_remote_tmp(ssh: SSHClientWrapper, options: Options) -> str:
    out, _, _ = ssh.run(f"mktemp -d {q(DEFAULT_REMOTE_TMP_PREFIX + 'XXXXXX')}", timeout=options.remote_cmd_timeout)
    remote_tmp = out.strip()
    if not remote_tmp.startswith(DEFAULT_REMOTE_TMP_PREFIX.rstrip(".")):
        raise ServiceError("REMOTE_TMP_INVALID", f"unsafe remote tmp dir: {remote_tmp}", http_status=502)
    return remote_tmp

def clean_remote_tmp(ssh: SSHClientWrapper, remote_tmp: str, options: Options, warnings: list[WarningItem]) -> None:
    if not remote_tmp or not remote_tmp.startswith(DEFAULT_REMOTE_TMP_PREFIX.rstrip(".")):
        warnings.append(WarningItem("REMOTE_TMP_CLEAN_SKIPPED", f"skip unsafe remote tmp clean: {remote_tmp}"))
        return
    try:
        ssh.run(f"rm -rf -- {q(remote_tmp)}", timeout=options.remote_cmd_timeout, check=False)
    except Exception as e:
        warnings.append(WarningItem("REMOTE_TMP_CLEAN_FAILED", f"remote tmp clean failed: {e}"))

def safe_extract_tar(tar_path: pathlib.Path, dest_dir: pathlib.Path) -> None:
    dest_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tar_path, "r:*") as tf:
        for member in tf.getmembers():
            target = (dest_dir / member.name).resolve()
            if not str(target).startswith(str(dest_dir.resolve())):
                raise ServiceError("TAR_UNSAFE_ENTRY", f"unsafe tar entry: {member.name}")
        tf.extractall(dest_dir)

def is_zip_log_file(file: RemoteLogFile) -> bool:
    return file.name.lower().endswith(".zip")

def split_active_and_archive_files(files: list[RemoteLogFile]) -> tuple[list[RemoteLogFile], list[RemoteLogFile]]:
    active_files, archive_files = [], []
    for file in files:
        (archive_files if is_zip_log_file(file) else active_files).append(file)
    return active_files, archive_files

def copy_active_file_to_node_tmp_by_cat(ssh: SSHClientWrapper, target: K8sTarget, file: RemoteLogFile, remote_tmp: str, options: Options, warnings: list[WarningItem]) -> None:
    dest_path = remote_tmp.rstrip("/") + "/" + file.name
    inner_cat = f"cat {q(file.remote_path)}"
    kubectl_cat = (
        f"kubectl exec -n {q(target.namespace)} {q(target.pod)} -c {q(target.container)}"
        f"{(' --user=' + q(options.container_user)) if options.container_user else ''} -- sh -c {q(inner_cat)}"
    )
    node_cmd = f"bash -lc {q('set -euo pipefail; ' + kubectl_cat + ' > ' + q(dest_path))}"
    out, err, code = ssh.run(node_cmd, timeout=options.remote_cmd_timeout, check=False)
    if code != 0:
        if options.container_user and ("unknown flag" in err.lower() or "flag provided but not defined" in err.lower()):
            raise ServiceError("KUBECTL_USER_NOT_SUPPORTED", "kubectl exec does not support --user in this environment", http_status=502, details=err[-2000:])
        raise ServiceError("REMOTE_CAT_FAILED", f"container active log cat failed for pod {target.pod}", http_status=502, details={
            "cmd": node_cmd, "stdout": out[-4000:], "stderr": err[-4000:], "pod": target.pod,
            "container": target.container, "remote_path": file.remote_path, "dest_path": dest_path,
        })
    warnings.append(WarningItem("ACTIVE_LOG_COPIED_BY_CAT", f"active log copied by cat for pod {target.pod}", file=file.remote_path))

def fetch_logs_compatible_batch(ssh: SSHClientWrapper, batch: ResolvedLogBatch, dest_dir: pathlib.Path, options: Options, warnings: list[WarningItem]) -> None:
    remote_tmp = ""
    try:
        remote_tmp = make_remote_tmp(ssh, options)
        by_base: dict[str, list[RemoteLogFile]] = {}
        for f in batch.remote_files:
            by_base.setdefault(f.base_path, []).append(f)
        for base_path, group in by_base.items():
            active_files, archive_files = split_active_and_archive_files(group)
            for file in active_files:
                copy_active_file_to_node_tmp_by_cat(ssh, batch.target, file, remote_tmp, options, warnings)
            if archive_files:
                names = " ".join(q(f.name) for f in archive_files)
                inner_tar = (
                    f"kubectl exec -n {q(batch.target.namespace)} {q(batch.target.pod)} -c {q(batch.target.container)}"
                    f"{(' --user=' + q(options.container_user)) if options.container_user else ''} -- "
                    f"tar -C {q(base_path)} -cf - {names}"
                )
                node_cmd = f"bash -lc {q('set -euo pipefail; ' + inner_tar + ' | tar -C ' + q(remote_tmp) + ' -xf -')}"
                try:
                    ssh.run(node_cmd, timeout=options.remote_cmd_timeout)
                except ServiceError as e:
                    if options.container_user and e.details and "unknown flag" in stable_json(e.details).lower():
                        raise ServiceError("KUBECTL_USER_NOT_SUPPORTED", "kubectl exec does not support --user in this environment", http_status=502, details=e.details)
                    raise ServiceError("REMOTE_TAR_FAILED", f"container archive tar failed for pod {batch.target.pod}", http_status=502, details={
                        "pod": batch.target.pod, "container": batch.target.container, "base_path": base_path,
                        "files": [f.name for f in archive_files], "cause": e.details,
                    }) from e
        sftp = ssh.open_sftp()
        try:
            download_sftp_dir(sftp, remote_tmp, dest_dir)
        finally:
            sftp.close()
    finally:
        if remote_tmp:
            clean_remote_tmp(ssh, remote_tmp, options, warnings)

def fetch_active_file_stream_by_cat(ssh: SSHClientWrapper, target: K8sTarget, file: RemoteLogFile, dest_dir: pathlib.Path, options: Options) -> None:
    dest_dir.mkdir(parents=True, exist_ok=True)
    local_path = dest_dir / file.name
    part_path = dest_dir / f"{file.name}.part-{os.getpid()}-{int(time.time() * 1000)}"
    cmd = (
        f"kubectl exec -n {q(target.namespace)} {q(target.pod)} -c {q(target.container)}"
        f"{(' --user=' + q(options.container_user)) if options.container_user else ''} -- "
        f"sh -c {q('cat ' + q(file.remote_path))}"
    )
    stdin, stdout, stderr = ssh.client.exec_command(cmd, timeout=options.remote_cmd_timeout)
    del stdin
    err_chunks: list[bytes] = []
    channel = stdout.channel
    try:
        with part_path.open("wb") as f:
            while True:
                if channel.recv_ready():
                    chunk = channel.recv(1024 * 1024)
                    if chunk:
                        f.write(chunk)
                if channel.recv_stderr_ready():
                    err = channel.recv_stderr(8192)
                    if err:
                        err_chunks.append(err)
                        if sum(len(x) for x in err_chunks) > 65536:
                            err_chunks = [b"".join(err_chunks)[-65536:]]
                if channel.exit_status_ready():
                    while channel.recv_ready():
                        chunk = channel.recv(1024 * 1024)
                        if chunk:
                            f.write(chunk)
                    while channel.recv_stderr_ready():
                        err = channel.recv_stderr(8192)
                        if err:
                            err_chunks.append(err)
                    break
                time.sleep(0.01)
        code = channel.recv_exit_status()
        err_text = b"".join(err_chunks).decode("utf-8", errors="replace")
        if code != 0:
            part_path.unlink(missing_ok=True)
            if options.container_user and ("unknown flag" in err_text.lower() or "flag provided but not defined" in err_text.lower()):
                raise ServiceError("KUBECTL_USER_NOT_SUPPORTED", "kubectl exec does not support --user in this environment", http_status=502, details=err_text[-4000:])
            raise ServiceError("REMOTE_CAT_FAILED", f"stream cat failed for pod {target.pod}", http_status=502, details={
                "cmd": cmd, "stderr": err_text[-4000:], "pod": target.pod, "container": target.container,
                "remote_path": file.remote_path, "local_path": str(local_path),
            })
        os.replace(part_path, local_path)
    except Exception:
        part_path.unlink(missing_ok=True)
        raise

def fetch_logs_stream_batch(ssh: SSHClientWrapper, batch: ResolvedLogBatch, dest_dir: pathlib.Path, options: Options, warnings: list[WarningItem]) -> None:
    dest_dir.mkdir(parents=True, exist_ok=True)
    by_base: dict[str, list[RemoteLogFile]] = {}
    for f in batch.remote_files:
        by_base.setdefault(f.base_path, []).append(f)
    for base_path, group in by_base.items():
        active_files, archive_files = split_active_and_archive_files(group)
        for file in active_files:
            fetch_active_file_stream_by_cat(ssh, batch.target, file, dest_dir, options)
            warnings.append(WarningItem("ACTIVE_LOG_STREAMED_BY_CAT", f"active log streamed by cat for pod {batch.target.pod}", file=file.remote_path))
        if not archive_files:
            continue
        names = " ".join(q(f.name) for f in archive_files)
        cmd = (
            f"kubectl exec -n {q(batch.target.namespace)} {q(batch.target.pod)} -c {q(batch.target.container)}"
            f"{(' --user=' + q(options.container_user)) if options.container_user else ''} -- "
            f"tar -C {q(base_path)} -cf - {names}"
        )
        tar_tmp = dest_dir / f"stream-{batch.remote_files[0].source_id}-{sha256_text(base_path)[:12]}.tar.part"
        stdin, stdout, stderr = ssh.client.exec_command(cmd, timeout=options.remote_cmd_timeout)
        del stdin
        with tar_tmp.open("wb") as f:
            while True:
                chunk = stdout.channel.recv(1024 * 1024)
                if not chunk:
                    break
                f.write(chunk)
        err = stderr.read().decode("utf-8", errors="replace")
        code = stdout.channel.recv_exit_status()
        if code != 0:
            tar_tmp.unlink(missing_ok=True)
            if options.container_user and ("unknown flag" in err.lower() or "flag provided but not defined" in err.lower()):
                raise ServiceError("KUBECTL_USER_NOT_SUPPORTED", "kubectl exec does not support --user in this environment", http_status=502, details=err[-2000:])
            raise ServiceError("REMOTE_TAR_FAILED", f"stream archive tar failed for pod {batch.target.pod}", http_status=502, details={
                "cmd": cmd, "stderr": err[-4000:], "pod": batch.target.pod, "base_path": base_path,
                "files": [f.name for f in archive_files],
            })
        safe_extract_tar(tar_tmp, dest_dir)
        tar_tmp.unlink(missing_ok=True)

def fetch_logs(ssh: SSHClientWrapper, batches: list[ResolvedLogBatch], cache_key: str, options: Options, warnings: list[WarningItem]) -> tuple[pathlib.Path, list[ResolvedLogBatch]]:
    CACHE.gc_if_needed(options, warnings)
    cache_dir = CACHE.cache_dir(cache_key)
    staging = cache_dir.with_name(cache_dir.name + f".part-{os.getpid()}-{int(time.time() * 1000)}")
    files_dir = staging / "files"
    staging.mkdir(parents=True, exist_ok=True)
    success_batches = 0
    failed_batches: list[dict[str, Any]] = []
    successful_batches: list[ResolvedLogBatch] = []
    try:
        for batch in batches:
            if not batch.remote_files:
                continue
            source_id = batch.remote_files[0].source_id
            dest_dir = files_dir / source_id
            dest_dir.mkdir(parents=True, exist_ok=True)
            try:
                if options.transfer_mode == TRANSFER_COMPATIBLE:
                    fetch_logs_compatible_batch(ssh, batch, dest_dir, options, warnings)
                elif options.transfer_mode == TRANSFER_STREAM:
                    fetch_logs_stream_batch(ssh, batch, dest_dir, options, warnings)
                else:
                    raise ServiceError("INVALID_REQUEST", f"unsupported transfer_mode: {options.transfer_mode}")
                success_batches += 1
                successful_batches.append(batch)
            except ServiceError as e:
                details = {
                    "pod": batch.target.pod, "namespace": batch.target.namespace, "container": batch.target.container,
                    "base_path": batch.base_path, "files": [f.name for f in batch.remote_files],
                    "code": e.code, "message": e.message, "details": e.details,
                }
                failed_batches.append(details)
                if options.pod_match_policy == POD_MATCH_ALL:
                    warnings.append(WarningItem("POD_LOG_FETCH_FAILED", f"fetch logs failed for pod {batch.target.pod}; skip this pod", details=details))
                    shutil.rmtree(dest_dir, ignore_errors=True)
                    continue
                raise
        if success_batches <= 0:
            raise ServiceError("ALL_POD_LOG_FETCH_FAILED", "all matched pods failed to fetch logs", http_status=502, details=failed_batches)
        if cache_dir.exists():
            shutil.rmtree(cache_dir)
        cache_dir.parent.mkdir(parents=True, exist_ok=True)
        os.replace(staging, cache_dir)
        return cache_dir / "files", successful_batches
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
