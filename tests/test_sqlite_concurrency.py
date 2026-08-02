import threading
import time
import unittest

from src.models import ServiceError
from sqlite_concurrency import SQLiteConcurrencyConfig, SQLiteSourceLimiter


class SQLiteSourceLimiterTests(unittest.TestCase):
    def test_same_source_waits_for_slot(self):
        limiter = SQLiteSourceLimiter(SQLiteConcurrencyConfig(
            max_per_source=1,
            max_waiters=2,
            acquire_timeout_seconds=0.5,
        ))
        entered = threading.Event()
        release = threading.Event()
        second_entered = threading.Event()

        def first():
            with limiter.acquire("source"):
                entered.set()
                release.wait(1)

        def second():
            entered.wait(1)
            with limiter.acquire("source"):
                second_entered.set()

        t1 = threading.Thread(target=first)
        t2 = threading.Thread(target=second)
        t1.start()
        t2.start()
        entered.wait(1)
        time.sleep(0.05)
        self.assertFalse(second_entered.is_set())
        release.set()
        t1.join(1)
        t2.join(1)
        self.assertTrue(second_entered.is_set())

    def test_acquire_timeout(self):
        limiter = SQLiteSourceLimiter(SQLiteConcurrencyConfig(
            max_per_source=1,
            max_waiters=1,
            acquire_timeout_seconds=0.03,
        ))
        with limiter.acquire("source"):
            with self.assertRaises(ServiceError) as ctx:
                with limiter.acquire("source"):
                    pass
        self.assertEqual(ctx.exception.code, "SQLITE_SOURCE_ACQUIRE_TIMEOUT")

    def test_queue_full(self):
        limiter = SQLiteSourceLimiter(SQLiteConcurrencyConfig(
            max_per_source=1,
            max_waiters=0,
            acquire_timeout_seconds=0.1,
        ))
        with limiter.acquire("source"):
            with self.assertRaises(ServiceError) as ctx:
                with limiter.acquire("source"):
                    pass
        self.assertEqual(ctx.exception.code, "SQLITE_SOURCE_QUEUE_FULL")


if __name__ == "__main__":
    unittest.main()
