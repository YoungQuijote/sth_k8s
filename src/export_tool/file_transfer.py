#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""独立于日志缓存的通用容器文件传输门面。"""

from __future__ import annotations

import pathlib

from src.export_tool.file_export_models import FileExportOptions
from src.log_fetcher import (
    clean_remote_tmp,
    copy_active_file_to_node_tmp_by_cat,
    download_sftp_dir,
    fetch_active_file_stream_by_cat,
    make_remote_tmp,
)
from src.models import ResolvedLogBatch, ServiceError, WarningItem, TRANSFER_COMPATIBLE, TRANSFER_STREAM
from src.utils.ssh_utils import SSHClientWrapper

_NORMAL_TRANSFER_CODES = {"ACTIVE_LOG_COPIED_BY_CAT", "ACTIVE_LOG_STREAMED_BY_CAT"}


def _append_meaningful_warnings(target: list[WarningItem], source: list[WarningItem]) -> None:
    target.extend(item for item in source if item.code not in _NORMAL_TRANSFER_CODES)


def _transfer_compatible(
    ssh: SSHClientWrapper,
    batch: ResolvedLogBatch,
    dest_dir: pathlib.Path,
    options: FileExportOptions,
    warnings: list[WarningItem],
) -> None:
    remote_tmp = ""
    transfer_warnings: list[WarningItem] = []
    try:
        remote_tmp = make_remote_tmp(ssh, options)
        for remote_file in batch.remote_files:
            copy_active_file_to_node_tmp_by_cat(
                ssh,
                batch.target,
                remote_file,
                remote_tmp,
                options,
                transfer_warnings,
            )
        sftp = ssh.open_sftp()
        try:
            download_sftp_dir(sftp, remote_tmp, dest_dir)
        finally:
            sftp.close()
    finally:
        if remote_tmp:
            clean_remote_tmp(ssh, remote_tmp, options, transfer_warnings)
        _append_meaningful_warnings(warnings, transfer_warnings)


def _transfer_stream(
    ssh: SSHClientWrapper,
    batch: ResolvedLogBatch,
    dest_dir: pathlib.Path,
    options: FileExportOptions,
) -> None:
    dest_dir.mkdir(parents=True, exist_ok=True)
    for remote_file in batch.remote_files:
        fetch_active_file_stream_by_cat(ssh, batch.target, remote_file, dest_dir, options)


def transfer_resolved_batch(
    ssh: SSHClientWrapper,
    batch: ResolvedLogBatch,
    dest_dir: pathlib.Path,
    options: FileExportOptions,
    warnings: list[WarningItem],
) -> None:
    """原样复制一个已解析文件批次；不写日志缓存、不解压文件。"""
    if options.transfer_mode == TRANSFER_COMPATIBLE:
        _transfer_compatible(ssh, batch, dest_dir, options, warnings)
        return
    if options.transfer_mode == TRANSFER_STREAM:
        _transfer_stream(ssh, batch, dest_dir, options)
        return
    raise ServiceError("INVALID_REQUEST", f"unsupported transfer_mode: {options.transfer_mode}")
