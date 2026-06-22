"""SMTP-level rate limiter — protects the gateway against email bombing.

Three independent sliding-window counters:

  Per-IP        max 10 emails / 60 seconds
  Per-domain    max 20 emails / 3600 seconds (1 hour)
  Global        max 60 emails / 60 seconds

If any counter is exceeded the handler returns SMTP 421 (temporary
failure). The sending MTA will retry later, so no legitimate email
is permanently lost.

Bombing alert: if 5+ emails from the same IP or domain arrive within
10 seconds a Slack alert fires once per source (suppressed for 5 min
afterwards to avoid alert fatigue).
"""
import time
import threading
from collections import deque

import structlog

logger = structlog.get_logger()

# ── Tunable limits ────────────────────────────────────────────────────────────
PER_IP_LIMIT     = 10    # emails per IP per minute
PER_DOMAIN_LIMIT = 20    # emails per sender domain per hour
GLOBAL_LIMIT     = 60    # emails total per minute

BURST_WINDOW     = 10    # seconds — detect rapid bursts
BURST_THRESHOLD  = 5     # emails within BURST_WINDOW = bombing

ALERT_SUPPRESS   = 300   # seconds — don't re-alert same source within 5 min

# ── State ─────────────────────────────────────────────────────────────────────
_lock          = threading.Lock()
_ip_windows:  dict[str, deque] = {}
_dom_windows: dict[str, deque] = {}
_global_window: deque          = deque()
_burst_windows: dict[str, deque] = {}
_alerted_at:   dict[str, float]  = {}   # source → last alert timestamp


def _sliding_count(dq: deque, window_secs: int, now: float) -> int:
    while dq and dq[0] < now - window_secs:
        dq.popleft()
    return len(dq)


def _sender_domain(sender_email: str) -> str:
    if not sender_email:
        return "unknown"
    addr = sender_email.strip().lower()
    if "<" in addr:
        addr = addr.split("<", 1)[1].split(">", 1)[0]
    return addr.split("@")[-1] if "@" in addr else addr


def check(peer_ip: str, sender_email: str) -> tuple[bool, str]:
    """
    Return (allowed, reason).
    allowed=True  → proceed with analysis
    allowed=False → return SMTP 421, reason contains the message
    """
    now   = time.monotonic()
    domain = _sender_domain(sender_email)

    with _lock:
        # ── Per-IP ────────────────────────────────────────────────────────────
        if peer_ip not in _ip_windows:
            _ip_windows[peer_ip] = deque()
        ip_dq = _ip_windows[peer_ip]
        ip_count = _sliding_count(ip_dq, 60, now)
        if ip_count >= PER_IP_LIMIT:
            logger.warning("smtp_rate_limit_ip", ip=peer_ip, count=ip_count)
            return False, f"421 Rate limit exceeded — {peer_ip} sent {ip_count} emails in 60s, limit {PER_IP_LIMIT}"

        # ── Per-domain ────────────────────────────────────────────────────────
        if domain not in _dom_windows:
            _dom_windows[domain] = deque()
        dom_dq = _dom_windows[domain]
        dom_count = _sliding_count(dom_dq, 3600, now)
        if dom_count >= PER_DOMAIN_LIMIT:
            logger.warning("smtp_rate_limit_domain", domain=domain, count=dom_count)
            return False, f"421 Rate limit exceeded — {domain} sent {dom_count} emails this hour, limit {PER_DOMAIN_LIMIT}"

        # ── Global ────────────────────────────────────────────────────────────
        global_count = _sliding_count(_global_window, 60, now)
        if global_count >= GLOBAL_LIMIT:
            logger.warning("smtp_rate_limit_global", count=global_count)
            return False, f"421 Service busy — global rate limit {GLOBAL_LIMIT}/min reached, try again shortly"

        # ── Record this email ─────────────────────────────────────────────────
        ip_dq.append(now)
        dom_dq.append(now)
        _global_window.append(now)

        # ── Burst detection ───────────────────────────────────────────────────
        for source_key in (peer_ip, domain):
            if source_key not in _burst_windows:
                _burst_windows[source_key] = deque()
            burst_dq = _burst_windows[source_key]
            burst_count = _sliding_count(burst_dq, BURST_WINDOW, now) + 1
            burst_dq.append(now)

            if burst_count >= BURST_THRESHOLD:
                last_alert = _alerted_at.get(source_key, 0)
                if now - last_alert > ALERT_SUPPRESS:
                    _alerted_at[source_key] = now
                    logger.warning(
                        "smtp_bombing_detected",
                        source=source_key,
                        count=burst_count,
                        window_secs=BURST_WINDOW,
                    )
                    # Fire Slack alert in background — don't block email processing
                    _alert_bombing_async(source_key, burst_count, peer_ip, sender_email)

    return True, ""


def _alert_bombing_async(source: str, count: int, peer_ip: str, sender: str) -> None:
    """Fire a Slack bombing alert in a daemon thread so it doesn't slow SMTP."""
    import threading as _thr

    def _send():
        try:
            import httpx, os
            webhook = os.environ.get("SLACK_WEBHOOK_URL", "")
            if not webhook:
                return
            import httpx as _hx
            payload = {
                "blocks": [
                    {"type": "header", "text": {"type": "plain_text",
                        "text": "🚨 PhishGuard — Email Bombing Detected"}},
                    {"type": "section", "fields": [
                        {"type": "mrkdwn", "text": f"*Source:* `{source}`"},
                        {"type": "mrkdwn", "text": f"*Sender:* `{sender}`"},
                        {"type": "mrkdwn", "text": f"*Peer IP:* `{peer_ip}`"},
                        {"type": "mrkdwn", "text": f"*Burst:* {count} emails in {BURST_WINDOW}s"},
                    ]},
                    {"type": "section", "text": {"type": "mrkdwn",
                        "text": "_Rate limiting applied. Legitimate emails will be retried by the sending MTA._"}},
                ]
            }
            _hx.post(webhook, json=payload, timeout=10)
        except Exception as exc:
            logger.warning("smtp_bombing_alert_err", error=str(exc))

    _thr.Thread(target=_send, daemon=True, name="bombing-alert").start()


def stats() -> dict:
    """Return current rate limiter state for the health/status endpoint."""
    now = time.monotonic()
    with _lock:
        return {
            "global_emails_last_minute": _sliding_count(deque(_global_window), 60, now),
            "tracked_ips":    len(_ip_windows),
            "tracked_domains": len(_dom_windows),
            "limits": {
                "per_ip_per_minute":    PER_IP_LIMIT,
                "per_domain_per_hour":  PER_DOMAIN_LIMIT,
                "global_per_minute":    GLOBAL_LIMIT,
                "burst_threshold":      BURST_THRESHOLD,
                "burst_window_secs":    BURST_WINDOW,
            },
        }
