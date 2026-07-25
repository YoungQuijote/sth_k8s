import gzip
import pathlib
import subprocess
import sys
import tempfile
import unittest

from gzip_utils import (
    REAL_TIME_GZIP_TAIL_SCRIPT,
    get_cached_gzip_extract,
    is_gzip_path,
    safe_extract_gzip,
)
from models import (
    ExtractRequest,
    LocalLogFile,
    Options,
    SegmentRule,
    Selector,
    SSHInfo,
)
from read_utils import scan_logs


class GzipLogSupportTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp_dir.name)
        self.lines = [
            f'{{"chat_id":"chat-{idx}","value":"value-{idx}"}}'
            for idx in range(40)
        ]
        self.raw = ("\n".join(self.lines) + "\n").encode("utf-8")
        self.gzip_path = self.root / "events.ndjson.gz"
        with gzip.open(self.gzip_path, "wb") as stream:
            stream.write(self.raw)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_magic_and_safe_extract(self):
        self.assertTrue(is_gzip_path(self.gzip_path))
        warnings = []
        extracted = safe_extract_gzip(
            self.gzip_path,
            self.root / "extract",
            Options(),
            warnings,
        )
        self.assertIsNotNone(extracted)
        self.assertEqual(extracted.name, "events.ndjson")
        self.assertEqual(extracted.read_bytes(), self.raw)
        self.assertEqual(warnings, [])

    def test_cached_extract_is_reused(self):
        warnings = []
        first = get_cached_gzip_extract(self.gzip_path, Options(), warnings)
        second = get_cached_gzip_extract(self.gzip_path, Options(), warnings)
        self.assertEqual(first, second)
        self.assertEqual(first[0].read_bytes(), self.raw)
        self.assertTrue((first[0].parent / ".meta.json").is_file())

    def test_uncompressed_limit_is_hard_failure(self):
        large_path = self.root / "large.ndjson.gz"
        with gzip.open(large_path, "wb") as stream:
            stream.write(b"x" * (1024 * 1024 + 1))
        warnings = []
        extracted = safe_extract_gzip(
            large_path,
            self.root / "large-extract",
            Options(max_zip_uncompressed_size_mb=1),
            warnings,
        )
        self.assertIsNone(extracted)
        self.assertEqual(warnings[-1].code, "GZIP_TOO_LARGE")

    def test_remote_script_returns_decompressed_tail(self):
        tail_bytes = 137
        process = subprocess.run(
            [
                sys.executable,
                "-c",
                REAL_TIME_GZIP_TAIL_SCRIPT,
                str(self.gzip_path),
                str(tail_bytes),
                str(16 * 1024 * 1024),
            ],
            capture_output=True,
            check=False,
        )
        self.assertEqual(process.returncode, 0, process.stderr.decode("utf-8", errors="replace"))
        self.assertEqual(process.stdout, self.raw[-tail_bytes:])

    def test_remote_script_rejects_oversized_stream(self):
        process = subprocess.run(
            [sys.executable, "-c", REAL_TIME_GZIP_TAIL_SCRIPT, str(self.gzip_path), "100", "10"],
            capture_output=True,
            check=False,
        )
        self.assertEqual(process.returncode, 13)
        self.assertIn(b"exceeded", process.stderr)

    def test_scan_logs_reads_ndjson_gzip(self):
        request = ExtractRequest(
            ssh=SSHInfo(host="127.0.0.1", port=22, username="root"),
            selector=Selector(namespace="ns", pod="pod", container="container"),
            path_segments=[SegmentRule(mode="exact", value="tmp")],
            log_file=SegmentRule(mode="regex", value=r".*\.ndjson\.gz$"),
            chat_ids=["chat-7"],
            field="custom",
            coarse_regex=r'"chat_id":"(?P<chat_id>[^"]+)".*?"value":"(?P<value>[^"]+)"',
            options=Options(max_matches_per_chat_id=1),
        )
        local_file = LocalLogFile(
            local_path=str(self.gzip_path),
            remote_path="/logs/events.ndjson.gz",
            name=self.gzip_path.name,
            mtime=1.0,
            size=self.gzip_path.stat().st_size,
        )
        warnings = []
        result = scan_logs(request, [local_file], warnings)
        self.assertEqual(result["items"][0]["matches"], ["value-7"])
        self.assertEqual(result["missed_chat_ids"], [])
        self.assertEqual(warnings, [])

    def test_tar_gzip_is_not_treated_as_single_log(self):
        tar_gzip = self.root / "archive.tar.gz"
        tar_gzip.write_bytes(self.gzip_path.read_bytes())
        warnings = []
        extracted = safe_extract_gzip(tar_gzip, self.root / "tar-extract", Options(), warnings)
        self.assertIsNone(extracted)
        self.assertEqual(warnings[-1].code, "GZIP_TAR_ARCHIVE_NOT_SUPPORTED")


if __name__ == "__main__":
    unittest.main()
