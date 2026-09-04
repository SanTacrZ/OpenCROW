"""Rate-limit guards for constellation auth paths.

Only failures are counted: N bad system tokens from one IP, or N bad
single-use passwords on one topic, flip 401/403 to 429 + Retry-After.
Valid traffic (UI polling, runtime heartbeats) never trips the limiter.
"""
import json
import threading
from unittest.mock import MagicMock

from tornado.testing import AsyncHTTPTestCase

from constellation.backend import AppState, RateLimiter, build_app
from constellation.config import BackendSettings


def _settings(**overrides):
    values = {
        "mongo_uri": "mongodb://127.0.0.1:27017",
        "mongo_db_name": "test",
        "listen_host": "127.0.0.1",
        "listen_port": 1,
        "system_tokens": ("good",),
        "broker_event_ttl_hours": 24,
        "allowed_ws_origins": (),
        "ui_shared_secret": None,
        "rate_limit_max_attempts": 3,
        "rate_limit_window_sec": 60.0,
    }
    values.update(overrides)
    return BackendSettings(**values)


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_limiter_trips_then_expires():
    clock = FakeClock()
    limiter = RateLimiter(max_attempts=3, window_sec=60.0, clock=clock)
    assert [limiter.exceeded("k") for _ in range(3)] == [None, None, None]
    retry = limiter.exceeded("k")
    assert retry is not None and retry > 0
    clock.now += 61.0
    assert limiter.exceeded("k") is None


def test_limiter_isolates_keys_and_clears():
    clock = FakeClock()
    limiter = RateLimiter(max_attempts=1, window_sec=60.0, clock=clock)
    assert limiter.exceeded("a") is None
    assert limiter.exceeded("a") is not None
    assert limiter.exceeded("b") is None
    limiter.clear("a")
    assert limiter.exceeded("a") is None


def test_limiter_thread_safe():
    limiter = RateLimiter(max_attempts=10000, window_sec=60.0)
    allowed = []
    lock = threading.Lock()

    def hit():
        if limiter.exceeded("k") is None:
            with lock:
                allowed.append(1)

    threads = [threading.Thread(target=hit) for _ in range(50)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert len(allowed) == 50


class AuthRateLimitTest(AsyncHTTPTestCase):
    def get_app(self):
        storage = MagicMock()
        storage.validate_system_token.return_value = False
        state = AppState(
            settings=_settings(),
            storage=storage,
            rate_limiter=RateLimiter(max_attempts=3, window_sec=60.0),
        )
        return build_app(state)

    def test_bad_tokens_flip_401_to_429(self):
        headers = {"Authorization": "Bearer wrong"}
        for _ in range(3):
            response = self.fetch("/api/v1/topics", headers=headers)
            assert response.code == 401
        limited = self.fetch("/api/v1/topics", headers=headers)
        assert limited.code == 429
        assert limited.headers.get("Retry-After")

    def test_health_never_rate_limited(self):
        for _ in range(5):
            response = self.fetch("/api/v1/health")
            assert response.code == 200


class ExchangeRateLimitTest(AsyncHTTPTestCase):
    def get_app(self):
        self.storage = MagicMock()
        self.storage.validate_system_token.return_value = True
        self.storage.exchange_admin_token.side_effect = PermissionError("bad password")
        state = AppState(
            settings=_settings(),
            storage=self.storage,
            rate_limiter=RateLimiter(max_attempts=2, window_sec=60.0),
        )
        return build_app(state)

    def _post(self):
        return self.fetch(
            "/api/v1/topics/t/admin/exchange",
            method="POST",
            headers={"Authorization": "Bearer good", "Content-Type": "application/json"},
            body=json.dumps({"member_id": "m", "single_use_password": "x"}),
        )

    def test_bad_passwords_flip_403_to_429(self):
        assert self._post().code == 403
        assert self._post().code == 403
        limited = self._post()
        assert limited.code == 429
        assert limited.headers.get("Retry-After")

    def test_success_clears_the_bucket(self):
        assert self._post().code == 403
        self.storage.exchange_admin_token.side_effect = None
        self.storage.exchange_admin_token.return_value = {"id": "m"}
        assert self._post().code == 200
        self.storage.exchange_admin_token.side_effect = PermissionError("bad password")
        assert self._post().code == 403
