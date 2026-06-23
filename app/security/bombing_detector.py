"""Email bombing detector — subscription bomb and inbox flooding detection.

Detects coordinated inbox bombing attacks where attackers sign the victim
up to hundreds of legitimate services (newsletters, e-commerce, forums)
causing a flood of SPF/DKIM-passing emails from diverse sources.

WHY THIS WORKS despite the attacker using 500 different legitimate domains:
  The attacker cannot change who the VICTIM is. The recipient address is
  the invariant. We detect the attack by watching the RECIPIENT, not the
  sender. Three signals must coalesce to avoid false positives:

  1. VOLUME SPIKE     — recipient receives N× baseline in a short window
  2. SUBJECT PATTERN  — majority match subscription/welcome/verify patterns
  3. SENDER DIVERSITY — most senders are domains never seen from before

All three together = subscription bomb with high confidence.
Any one alone = too many false positives (a real newsletter blast triggers
volume; a company all-hands triggers diversity; a welcome email is pattern).

Response:
  - Fires a dedicated Slack alert ("inbox under attack")
  - Marks recipient as UNDER_ATTACK for HOLD_MINUTES minutes
  - While under attack, ALL emails to that recipient are held for SOC
    review regardless of verdict — prevents real phishing/OTP being
    buried in the flood
"""
import re
import threading
import time
from collections import deque

import structlog

logger = structlog.get_logger()

# ── Tunable thresholds ────────────────────────────────────────────────────────
WINDOW_SECS          = 300      # 5-minute sliding detection window
VOLUME_THRESHOLD     = 20       # emails in window to consider "spike"
PATTERN_RATIO        = 0.60     # fraction of emails matching subscription pattern
DIVERSITY_RATIO      = 0.70     # fraction of emails from unseen sender domains
HOLD_MINUTES         = 20       # minutes to hold ALL emails after attack detected
ALERT_SUPPRESS_SECS  = 600      # don't re-alert same recipient within 10 min

# ── Early velocity detection (catches the attack sooner) ─────────────────────
# If VELOCITY_THRESHOLD subscription-pattern emails arrive within VELOCITY_WINDOW
# seconds that is clearly bot-speed behaviour — no human signs up to 5 newsletters
# in 30 seconds. Fire the hold immediately without waiting for VOLUME_THRESHOLD.
# Lower false-positive risk: pattern check is still required (not just raw volume).
VELOCITY_WINDOW      = 30       # seconds — short burst window
VELOCITY_THRESHOLD   = 5        # subscription-pattern emails in that window = bomb

# ── Subscription bomb subject patterns ───────────────────────────────────────
_SUBSCRIPTION_RES = [
    re.compile(p, re.IGNORECASE) for p in [
        r"confirm\s+(your\s+)?(email|account|subscription|registration|address)",
        r"verify\s+(your\s+)?(email|account|identity|address)",
        r"please\s+(confirm|verify|activate|validate)",
        r"welcome\s+to\s+",
        r"thanks?\s+for\s+(signing\s+up|registering|subscribing|joining)",
        r"activate\s+(your\s+)?(account|subscription|profile)",
        r"complete\s+(your\s+)?(registration|sign.?up|profile)",
        r"you.ve\s+(been\s+)?(registered|subscribed|signed\s+up|added)",
        r"action\s+required.{0,20}(account|email|subscription)",
        r"(email|account)\s+verification",
        r"finish\s+(setting\s+up|creating|your\s+registration)",
        r"one\s+more\s+step",
    ]
]


def _matches_subscription_pattern(subject: str) -> bool:
    s = subject.strip()
    return any(rx.search(s) for rx in _SUBSCRIPTION_RES)


def _sender_domain(sender: str) -> str:
    if not sender:
        return ""
    addr = sender.strip().lower()
    if "<" in addr:
        addr = addr.split("<", 1)[1].split(">", 1)[0]
    return addr.split("@")[-1] if "@" in addr else addr


# ── Per-recipient state ───────────────────────────────────────────────────────

class _RecipientState:
    __slots__ = (
        "arrivals",          # deque of (ts, sender_domain, is_pattern_match)
        "seen_domains",      # set of all domains ever seen for this recipient
        "under_attack_until",# monotonic timestamp when attack hold expires (0 = not active)
        "last_alerted",      # last time Slack alert fired
    )

    def __init__(self):
        self.arrivals:           deque  = deque()
        self.seen_domains:       set    = set()
        self.under_attack_until: float  = 0.0
        self.last_alerted:       float  = 0.0


_lock  = threading.Lock()
_state: dict[str, _RecipientState] = {}


def _get_or_create(rcpt: str) -> _RecipientState:
    if rcpt not in _state:
        _state[rcpt] = _RecipientState()
    return _state[rcpt]


def _prune_window(arrivals: deque, now: float) -> None:
    while arrivals and arrivals[0][0] < now - WINDOW_SECS:
        arrivals.popleft()


# ── Public API ────────────────────────────────────────────────────────────────

def record(rcpt: str, sender_email: str, subject: str) -> tuple[bool, bool]:
    """
    Record an arriving email and evaluate the bombing score.

    Returns:
      (is_under_attack, newly_detected)

      is_under_attack  — True if recipient is currently in the hold window
                         (caller should route to SOC Pending Review)
      newly_detected   — True if this call triggered the detection
                         (caller should fire a Slack alert)
    """
    if not rcpt:
        return False, False

    rcpt   = rcpt.strip().lower()
    domain = _sender_domain(sender_email)
    is_pattern = _matches_subscription_pattern(subject or "")
    now    = time.monotonic()

    with _lock:
        st = _get_or_create(rcpt)

        # Prune stale entries
        _prune_window(st.arrivals, now)

        # Record this email
        st.arrivals.append((now, domain, is_pattern))
        st.seen_domains.add(domain)

        # If already under attack, just extend visibility
        if now < st.under_attack_until:
            return True, False

        # ── Early velocity check (fires before VOLUME_THRESHOLD) ─────────────
        # If VELOCITY_THRESHOLD subscription-pattern emails arrive within
        # VELOCITY_WINDOW seconds → bot-speed sign-ups, hold immediately.
        # Pattern is required so a burst of legitimate direct emails (e.g.
        # company all-hands CC) doesn't trigger a false positive.
        velocity_window_emails = [e for e in st.arrivals if e[0] >= now - VELOCITY_WINDOW]
        velocity_pattern_count = sum(1 for _, _, p in velocity_window_emails if p)
        if velocity_pattern_count >= VELOCITY_THRESHOLD:
            st.under_attack_until = now + HOLD_MINUTES * 60
            if now - st.last_alerted > ALERT_SUPPRESS_SECS:
                st.last_alerted = now
                logger.warning(
                    "inbox_bombing_velocity_detected",
                    rcpt=rcpt,
                    pattern_emails_in_30s=velocity_pattern_count,
                    window_secs=VELOCITY_WINDOW,
                )
                _alert_async(rcpt, velocity_pattern_count, 1.0, 0.0,
                             trigger="velocity")
            return True, True

        # ── Full volume+pattern+diversity check ───────────────────────────────
        window = list(st.arrivals)  # snapshot
        n = len(window)

        if n < VOLUME_THRESHOLD:
            return False, False

        # Pattern ratio
        pattern_count = sum(1 for _, _, p in window if p)
        pattern_ratio = pattern_count / n

        # Sender diversity — fraction from domains NOT seen before this window
        window_domains = [d for _, d, _ in window]
        window_start_seen = st.seen_domains - set(window_domains)  # seen BEFORE window
        new_domain_count = sum(1 for d in window_domains if d not in window_start_seen)
        diversity_ratio = new_domain_count / n

        # All three signals must coalesce
        if pattern_ratio < PATTERN_RATIO or diversity_ratio < DIVERSITY_RATIO:
            return False, False

        # ── Bombing confirmed ─────────────────────────────────────────────────
        st.under_attack_until = now + HOLD_MINUTES * 60
        newly_detected = True

        logger.warning(
            "inbox_bombing_detected",
            rcpt=rcpt,
            emails_in_window=n,
            pattern_ratio=round(pattern_ratio, 2),
            diversity_ratio=round(diversity_ratio, 2),
            hold_until_mins=HOLD_MINUTES,
        )

        # Slack alert (suppressed if fired recently)
        if now - st.last_alerted > ALERT_SUPPRESS_SECS:
            st.last_alerted = now
            _alert_async(rcpt, n, pattern_ratio, diversity_ratio)

        return True, True


def is_under_attack(rcpt: str) -> bool:
    """Check if a recipient is currently in the hold window."""
    if not rcpt:
        return False
    rcpt = rcpt.strip().lower()
    now  = time.monotonic()
    with _lock:
        st = _state.get(rcpt)
        return bool(st and now < st.under_attack_until)


def clear_attack(rcpt: str) -> None:
    """SOC manually clears the bombing hold for a recipient."""
    rcpt = rcpt.strip().lower()
    with _lock:
        st = _state.get(rcpt)
        if st:
            st.under_attack_until = 0.0
    logger.info("inbox_bombing_cleared", rcpt=rcpt)


def active_attacks() -> list[dict]:
    """Return all recipients currently under a bombing hold."""
    now = time.monotonic()
    out = []
    with _lock:
        for rcpt, st in _state.items():
            if now < st.under_attack_until:
                window = list(st.arrivals)
                _prune_window(deque(window), now)
                n = len(window)
                secs_remaining = int(st.under_attack_until - now)
                out.append({
                    "rcpt": rcpt,
                    "emails_in_window": n,
                    "hold_expires_in_secs": secs_remaining,
                    "hold_expires_in_mins": round(secs_remaining / 60, 1),
                })
    return out


def stats() -> dict:
    now = time.monotonic()
    with _lock:
        attacks = [r for r, st in _state.items() if now < st.under_attack_until]
        return {
            "tracked_recipients": len(_state),
            "active_attacks":     len(attacks),
            "attacked_inboxes":   attacks,
            "thresholds": {
                "window_secs":       WINDOW_SECS,
                "volume_threshold":  VOLUME_THRESHOLD,
                "pattern_ratio":     PATTERN_RATIO,
                "diversity_ratio":   DIVERSITY_RATIO,
                "hold_minutes":      HOLD_MINUTES,
            },
        }


# ── Slack alert ───────────────────────────────────────────────────────────────

def _alert_async(rcpt: str, count: int, pattern_ratio: float, diversity_ratio: float,
                 trigger: str = "volume") -> None:
    import threading as _thr

    def _send():
        try:
            import httpx as _hx, os
            webhook = os.environ.get("SLACK_WEBHOOK_URL", "")
            if not webhook:
                return
            payload = {"blocks": [
                {"type": "header", "text": {"type": "plain_text",
                    "text": "🌊 PhishGuard — Inbox Bombing Attack Detected"}},
                {"type": "section", "fields": [
                    {"type": "mrkdwn", "text": f"*Target inbox:*\n`{rcpt}`"},
                    {"type": "mrkdwn", "text": f"*Emails in 5 min:*\n{count}"},
                    {"type": "mrkdwn", "text": f"*Subscription pattern:*\n{round(pattern_ratio*100)}% match"},
                    {"type": "mrkdwn", "text": f"*New sender domains:*\n{round(diversity_ratio*100)}% unseen"},
                ]},
                {"type": "section", "text": {"type": "mrkdwn",
                    "text": (
                        f"⚠️ *Subscription bomb in progress ({trigger} trigger).* "
                        f"All emails to `{rcpt}` are being "
                        f"held in SOC Pending Review for {HOLD_MINUTES} minutes to prevent real "
                        f"phishing or OTP emails from being buried in the flood.\n\n"
                        f"_SOC: review and bulk-approve legitimate emails, then clear the hold via dashboard._"
                    )}},
                {"type": "actions", "elements": [
                    {"type": "button", "text": {"type": "plain_text", "text": "Open Dashboard"},
                     "url": "http://localhost:8000", "style": "primary"},
                ]},
            ]}
            _hx.post(webhook, json=payload, timeout=10)
        except Exception as exc:
            logger.warning("bombing_alert_err", error=str(exc))

    _thr.Thread(target=_send, daemon=True, name="bombing-slack").start()
