import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from preset_scripts import SQLITE_QUERY_RESULT_MARKER, SQLITE_QUERY_SCRIPT


class SQLiteQueryScriptTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "state.db"
        connection = sqlite3.connect(self.db_path)
        connection.execute(
            "create table states(id integer, chat_id text, content text, payload blob)"
        )
        connection.executemany(
            "insert into states values(?,?,?,?)",
            [
                (1, "a", "alpha", b"\x00\x01"),
                (2, "a", "beta", b"\x02"),
                (3, "b", "gamma", None),
            ],
        )
        connection.commit()
        connection.close()

    def tearDown(self):
        self.temp_dir.cleanup()

    def execute(self, sql, *, result_mode="all", columns=None, max_rows=10):
        payload = {
            "sql": sql,
            "chat_ids": ["a", "b", "missing"],
            "result_mode": result_mode,
            "columns": columns or [],
            "sqlite_busy_timeout_ms": 1000,
            "query_timeout_seconds": 5,
            "limits": {
                "max_rows_per_chat_id": max_rows,
                "max_total_rows": 20,
                "max_result_size_bytes": 100000,
                "max_cell_size_bytes": 10000,
            },
        }
        completed = subprocess.run(
            [sys.executable, "-c", SQLITE_QUERY_SCRIPT, str(self.db_path)],
            input=json.dumps(payload).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        lines = [
            line
            for line in completed.stdout.decode("utf-8").splitlines()
            if line.startswith(SQLITE_QUERY_RESULT_MARKER)
        ]
        self.assertTrue(lines)
        return json.loads(lines[-1][len(SQLITE_QUERY_RESULT_MARKER):])

    def test_batch_query_and_blob_serialization(self):
        result = self.execute(
            "select id, chat_id, content, payload "
            "from states where chat_id=:chat_id order by id"
        )
        self.assertTrue(result["success"])
        self.assertEqual(result["items"][0]["row_count"], 2)
        self.assertEqual(result["items"][2]["row_count"], 0)
        self.assertEqual(result["items"][0]["rows"][0][3]["__type__"], "bytes")

    def test_columns_mode_filters_after_query(self):
        result = self.execute(
            "select id, content from states where chat_id=:chat_id order by id",
            result_mode="columns",
            columns=["content"],
        )
        self.assertTrue(result["success"])
        self.assertEqual(result["items"][0]["columns"], ["content"])
        self.assertEqual(result["items"][0]["rows"], [["alpha"], ["beta"]])

    def test_write_statement_is_denied(self):
        result = self.execute(
            "update states set content='changed' where chat_id=:chat_id"
        )
        self.assertFalse(result["success"])
        connection = sqlite3.connect(self.db_path)
        try:
            value = connection.execute(
                "select content from states where id=1"
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(value, "alpha")

    def test_row_limit_is_not_silently_truncated(self):
        result = self.execute(
            "select id from states where chat_id=:chat_id",
            max_rows=1,
        )
        self.assertFalse(result["success"])
        self.assertEqual(result["error"]["code"], "SQLITE_ROWS_LIMIT_EXCEEDED")


if __name__ == "__main__":
    unittest.main()
