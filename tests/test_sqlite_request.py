import unittest

import sqlite_request as sqlite_query
from src.models import SQLiteQuerySpec, ServiceError
from sqlite_rule import SQLITE_QUERY_RULES


class SQLiteRequestTests(unittest.TestCase):
    def setUp(self):
        self.old_token = sqlite_query.SQLITE_USER_SQL_AUTH_TOKEN
        sqlite_query.SQLITE_USER_SQL_AUTH_TOKEN = "secret"
        SQLITE_QUERY_RULES["state"] = SQLiteQuerySpec(
            "select id, content from states where chat_id=:chat_id"
        )
        self.base = {
            "ssh": {"host": "10.0.0.1", "username": "root", "password": "pwd"},
            "selector": {"namespace": "ns", "pod": "pod", "container": "ctr"},
            "path_segments": [
                {"mode": "exact", "value": "opt"},
                {"mode": "regex", "value": r"data\d+"},
            ],
            "sqlite_file": {"mode": "regex", "value": r".*\.db$"},
            "chat_ids": ["a", "a", "b"],
            "field": "state",
            "result_mode": "columns",
            "columns": ["id", "content"],
        }

    def tearDown(self):
        sqlite_query.SQLITE_USER_SQL_AUTH_TOKEN = self.old_token
        SQLITE_QUERY_RULES.pop("state", None)

    def test_field_request(self):
        req = sqlite_query.parse_sqlite_query_request(self.base)
        self.assertEqual(req.chat_ids, ["a", "b"])
        self.assertEqual(req.query_source, "field")
        self.assertEqual(req.field, "state")

    def test_user_sql_request(self):
        data = dict(self.base)
        data.pop("field")
        data.update({
            "user_sql": "select content from states where chat_id=:chat_id",
            "user_sql_auth": "secret",
            "result_mode": "all",
            "columns": [],
        })
        req = sqlite_query.parse_sqlite_query_request(data)
        self.assertEqual(req.query_source, "user_sql")
        self.assertIsNone(req.field)

    def test_field_and_user_sql_are_mutually_exclusive(self):
        data = dict(self.base)
        data.update({
            "user_sql": "select content from states where chat_id=:chat_id",
            "user_sql_auth": "secret",
        })
        with self.assertRaises(ServiceError):
            sqlite_query.parse_sqlite_query_request(data)

    def test_user_sql_requires_auth_and_chat_id_parameter(self):
        data = dict(self.base)
        data.pop("field")
        data.update({"user_sql": "select 1", "user_sql_auth": "secret"})
        with self.assertRaises(ServiceError) as ctx:
            sqlite_query.parse_sqlite_query_request(data)
        self.assertEqual(ctx.exception.code, "SQLITE_CHAT_ID_PARAMETER_MISSING")

        data["user_sql"] = "select 1 where :chat_id is not null"
        data["user_sql_auth"] = "wrong"
        with self.assertRaises(ServiceError) as ctx:
            sqlite_query.parse_sqlite_query_request(data)
        self.assertEqual(ctx.exception.code, "SQLITE_USER_SQL_UNAUTHORIZED")


if __name__ == "__main__":
    unittest.main()
