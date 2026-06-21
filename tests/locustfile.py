"""PhishGuard performance benchmark — Locust load test.

Usage:
    # Install: pip install locust
    # Run headless (100 concurrent users, 5 min):
    locust -f tests/locustfile.py --headless -u 100 -r 10 --run-time 5m \
        --host http://localhost:8000 --html tests/perf_report.html

    # Interactive UI:
    locust -f tests/locustfile.py --host http://localhost:8000

Targets from PRD Section 6.1:
    /analyze   p50 < 3s,   p99 < 30s   (full pipeline)
    /health    p99 < 200ms
    /api/stats p99 < 100ms

The benchmark uses a dev API key; set LOCUST_API_KEY env var to override.
"""
import os
import random

from locust import HttpUser, between, task

_API_KEY = os.environ.get("LOCUST_API_KEY", "dev-key")

# Pre-built payloads of varying complexity
_CLEAN_EMAIL = """From: alice@example.com
To: bob@company.com
Subject: Meeting notes
Date: Mon, 16 Jun 2026 10:00:00 +0000

Hi Bob, please find attached the notes from today's meeting.
"""

_PHISHING_EMAIL = """From: security@paypal-login-verify.com
To: victim@company.com
Subject: URGENT: Your PayPal account has been limited
Date: Mon, 16 Jun 2026 02:00:00 +0000

Dear Customer,

Your account has been limited due to suspicious activity.
Please verify your account within 24 hours or it will be closed.

Click here to verify: http://paypal-login-verify.xyz/confirm

PayPal Security Team
"""

_BEC_EMAIL = """From: ceo@company-executive.com
To: finance@company.com
Subject: Wire transfer request - URGENT
Date: Mon, 16 Jun 2026 11:30:00 +0000

Hi,

I need you to process an urgent wire transfer of $50,000 to:
Account: 1234567890
Bank: First National Bank
Routing: 021000021

Please do this immediately and confirm by email. Do not call me as I am in a meeting.

CEO
"""

_EMAILS = [_CLEAN_EMAIL, _PHISHING_EMAIL, _BEC_EMAIL]


def _get_token(client) -> str:
    """Obtain a JWT for the load test user."""
    r = client.post(
        "/token",
        json={"api_key": _API_KEY, "sub": "locust-user", "role": "analyst"},
        name="/token (auth)",
    )
    if r.status_code == 200:
        return r.json().get("access_token", "")
    return ""


class PhishGuardUser(HttpUser):
    """Simulates a SOC analyst using the PhishGuard API."""

    wait_time = between(0.5, 2)  # random think-time between tasks

    def on_start(self):
        self.token = _get_token(self.client)

    def _auth(self):
        return {"Authorization": f"Bearer {self.token}"}

    @task(5)
    def analyze_email(self):
        """POST /analyze — main scoring endpoint (5× weight in task mix)."""
        payload = random.choice(_EMAILS)
        self.client.post(
            "/analyze",
            json={"raw_email": payload},
            headers=self._auth(),
            name="/analyze",
        )

    @task(3)
    def health_check(self):
        """GET /health — should be very fast."""
        self.client.get("/health", name="/health")

    @task(2)
    def list_scans(self):
        """GET /api/scans — paginated scan list."""
        self.client.get(
            "/api/scans?limit=20",
            headers=self._auth(),
            name="/api/scans",
        )

    @task(1)
    def get_stats(self):
        """GET /api/stats — dashboard stats counters."""
        self.client.get("/api/stats", name="/api/stats")

    @task(1)
    def get_stats_24h(self):
        """GET /api/stats?hours=24 — time-filtered stats."""
        self.client.get("/api/stats?hours=24", name="/api/stats?hours=24")


class ReadOnlyUser(HttpUser):
    """Simulates a read-only dashboard viewer with no scanning."""

    wait_time = between(1, 3)
    weight = 2  # fewer read-only users than analysts

    def on_start(self):
        self.token = _get_token(self.client)

    @task(3)
    def poll_stats(self):
        self.client.get("/api/stats", name="/api/stats (ro)")

    @task(2)
    def poll_scans(self):
        self.client.get(
            "/api/scans?limit=10",
            headers={"Authorization": f"Bearer {self.token}"},
            name="/api/scans (ro)",
        )

    @task(1)
    def health(self):
        self.client.get("/health", name="/health (ro)")
