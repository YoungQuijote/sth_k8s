import threading
import time
import unittest

from src.models import SSHInfo, ServiceError
from src.utils.ssh_pool import SSHConnectionManager, SSHPoolConfig


class FakeClient:
    created = 0
    connect_delay = 0.0
    fail_connect = False

    def __init__(self, info):
        self.info = info
        self.active = False
        type(self).created += 1

    def connect(self):
        time.sleep(type(self).connect_delay)
        if type(self).fail_connect:
            raise OSError("connect failed")
        self.active = True
        return self

    def close(self):
        self.active = False

    def is_active(self):
        return self.active


class SSHPoolTests(unittest.TestCase):
    def setUp(self):
        FakeClient.created = 0
        FakeClient.connect_delay = 0.0
        FakeClient.fail_connect = False
        self.info = SSHInfo(host="10.0.0.1", port=22, username="root", password="pwd")

    def make_pool(self, **kwargs):
        config = SSHPoolConfig(
            global_max_connections=kwargs.get("global_max_connections", 4),
            target_max_connections=kwargs.get("target_max_connections", 2),
            max_waiters=kwargs.get("max_waiters", 10),
            acquire_timeout_seconds=kwargs.get("acquire_timeout_seconds", 0.2),
            idle_timeout_seconds=kwargs.get("idle_timeout_seconds", 1.0),
            max_lifetime_seconds=kwargs.get("max_lifetime_seconds", 10.0),
            connect_failure_cooldown_seconds=kwargs.get("connect_failure_cooldown_seconds", 0.2),
            reaper_interval_seconds=kwargs.get("reaper_interval_seconds", 0.02),
        )
        return SSHConnectionManager(FakeClient, config)

    def test_reuses_idle_connection(self):
        pool = self.make_pool()
        try:
            with pool.acquire(self.info) as first:
                pass
            with pool.acquire(self.info) as second:
                self.assertIs(first, second)
            self.assertEqual(FakeClient.created, 1)
        finally:
            pool.close()

    def test_same_connection_is_not_shared_concurrently(self):
        pool = self.make_pool(target_max_connections=1)
        entered = threading.Event()
        release = threading.Event()
        clients = []

        def first_request():
            with pool.acquire(self.info) as client:
                clients.append(client)
                entered.set()
                release.wait(1)

        def second_request():
            entered.wait(1)
            with pool.acquire(self.info) as client:
                clients.append(client)

        t1 = threading.Thread(target=first_request)
        t2 = threading.Thread(target=second_request)
        try:
            t1.start()
            t2.start()
            entered.wait(1)
            time.sleep(0.05)
            self.assertEqual(len(clients), 1)
            release.set()
            t1.join(1)
            t2.join(1)
            self.assertEqual(len(clients), 2)
            self.assertIs(clients[0], clients[1])
        finally:
            release.set()
            pool.close()

    def test_acquire_timeout(self):
        pool = self.make_pool(target_max_connections=1, acquire_timeout_seconds=0.05)
        release = threading.Event()

        def holder():
            with pool.acquire(self.info):
                release.wait(1)

        thread = threading.Thread(target=holder)
        try:
            thread.start()
            time.sleep(0.02)
            with self.assertRaises(ServiceError) as ctx:
                with pool.acquire(self.info):
                    pass
            self.assertEqual(ctx.exception.code, "SSH_POOL_ACQUIRE_TIMEOUT")
        finally:
            release.set()
            thread.join(1)
            pool.close()

    def test_idle_connection_is_reaped(self):
        pool = self.make_pool(idle_timeout_seconds=0.03, reaper_interval_seconds=0.01)
        try:
            with pool.acquire(self.info) as first:
                pass
            time.sleep(0.08)
            self.assertFalse(first.is_active())
            with pool.acquire(self.info) as second:
                self.assertIsNot(first, second)
        finally:
            pool.close()

    def test_connect_failure_uses_short_cooldown(self):
        pool = self.make_pool(connect_failure_cooldown_seconds=0.2)
        FakeClient.fail_connect = True
        try:
            with self.assertRaises(ServiceError):
                with pool.acquire(self.info):
                    pass
            first_count = FakeClient.created
            with self.assertRaises(ServiceError):
                with pool.acquire(self.info):
                    pass
            self.assertEqual(FakeClient.created, first_count)
        finally:
            pool.close()


if __name__ == "__main__":
    unittest.main()
