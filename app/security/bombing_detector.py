"""Email bombing detector — subscription bomb and inbox flooding detection.

DETECTION MODEL
===============
Three signals scored independently, combined as weighted sum (not hard AND).
This makes detection language-independent: volume + diversity alone is enough.
Subject pattern is a confidence booster, not a veto gate.

  Signal            Weight  Language-independent?
  Volume spike        40    Yes — raw count, no NLP
  Sender diversity    40    Yes — domain comparison
  Subject pattern     20    No  — English regex, optional

Detection fires when score >= DETECT_SCORE_THRESHOLD (default 60).
This means:
  volume + high diversity (non-English bomb)  = 80 → DETECTED
  volume + pattern (low-diversity newsletter) = 60 → DETECTED
  volume alone (company blast)                = 40 → not detected
  diversity + pattern (low volume)            =  0 → not detected (gated by volume)

EARLY VELOCITY PATH
===================
5 subscription-pattern emails in 30s = bot speed → hold immediately.
Fires before reaching volume threshold so first 4 emails arrive, hold is
active before email 5. Pattern still required to avoid false-positive on
legitimate email bursts (company all-hands CC).

SMART RESPONSE
==============
Holding ALL mail during a bombing attack can harm the user — the whole
point of the attack is to bury a real OTP/password-reset/bank alert.
Response is tiered:

  Email is HIGH-SIGNAL (OTP, reset, bank, security alert)
    → deliver immediately, tag PhishGuard-Priority
    → OTP never gets buried even during active bombing hold

  Email is subscription noise (matches subscription patterns)
    → hold for SOC review

  Email is neither (normal business email during hold window)
    → hold for SOC review (cautious, SOC can bulk-approve)

COLD-START GRACE PERIOD
========================
A new mailbox has seen 0 domains so diversity is always 100%.
When seen_domain history < COLD_START_MIN_HISTORY, the diversity signal
is downweighted so new employees are not flagged on first day.

MEMORY SAFETY
=============
seen_domains is capped at MAX_SEEN_DOMAINS per recipient. Arrivals deque
is pruned on every record() call — no unbounded growth.
"""
import re
import threading
import time
from collections import deque

import structlog

logger = structlog.get_logger()

# ── Tunable thresholds (can be overridden via env/config) ─────────────────────
WINDOW_SECS              = 300    # 5-minute main detection window
VOLUME_THRESHOLD         = 20     # min emails in window before scoring
DIVERSITY_RATIO          = 0.70   # fraction from unseen domains → high signal
PATTERN_RATIO            = 0.60   # fraction matching subscription subjects
DETECT_SCORE_THRESHOLD   = 60     # score ≥ this → bombing detected
HOLD_MINUTES             = 20     # hold duration after detection
ALERT_SUPPRESS_SECS      = 600    # suppress repeat Slack alerts per recipient

VELOCITY_WINDOW          = 30     # seconds for early velocity check
VELOCITY_THRESHOLD       = 5      # subscription emails in VELOCITY_WINDOW → bot

COLD_START_MIN_HISTORY   = 10     # min seen domains before diversity is trusted
MAX_SEEN_DOMAINS         = 500    # cap per recipient to bound memory

# ── Subscription subject patterns (confidence booster, not hard gate) ─────────
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

# ── High-signal subjects — surface immediately even during bombing hold ────────
_HIGH_SIGNAL_RES = [
    re.compile(p, re.IGNORECASE) for p in [
        r"(one.?time|otp|verification)\s*(code|password|pin)",
        r"(password|account)\s*reset",
        r"new\s*(device|sign.?in|login|location)\s*(detected|alert)?",
        r"security\s*(alert|code|notification|warning)",
        r"(payment|transaction|wire\s*transfer)\s*(alert|notification|received)?",
        r"unusual\s*(activity|sign.?in|access|login)",
        r"(your\s+)?(bank|financial)\s*(alert|notification|message)",
        r"(login|sign.?in)\s*(attempt|from\s+new)",
        r"your\s+(account|card)\s+(was|has\s+been)\s+(charged|debited|used)",
    ]
]


def is_high_signal(subject: str) -> bool:
    """True for emails that should bypass the bombing hold — OTPs, resets, bank alerts."""
    return any(rx.search(subject or "") for rx in _HIGH_SIGNAL_RES)


def _matches_subscription_pattern(subject: str) -> bool:
    return any(rx.search(subject or "") for rx in _SUBSCRIPTION_RES)


def _sender_domain(sender: str) -> str:
    if not sender:
        return ""
    addr = sender.strip().lower()
    if "<" in addr:
        addr = addr.split("<", 1)[1].split(">", 1)[0]
    return addr.split("@")[-1] if "@" in addr else addr


def _compute_score(n: int, pattern_ratio: float, diversity_ratio: float,
                   history_size: int) -> int:
    """
    Compute bombing confidence score 0–100.
    Volume gates everything. Diversity + pattern are independent signals.
    Cold-start: downweight diversity when history is thin.
    """
    if n < VOLUME_THRESHOLD:
        return 0

    score = 40  # volume threshold passed

    # Diversity signal (language-independent, strong)
    if history_size >= COLD_START_MIN_HISTORY:
        if diversity_ratio >= DIVERSITY_RATIO:
            score += 40
        elif diversity_ratio >= 0.50:
            score += 20
    else:
        # Not enough history — partial credit to avoid cold-start false negatives
        if diversity_ratio >= 0.90:
            score += 20   # extremely high diversity even without history = suspicious

    # Pattern signal (English, optional booster)
    if pattern_ratio >= PATTERN_RATIO:
        score += 20
    elif pattern_ratio >= 0.30:
        score += 10

    return score


# ── Per-recipient state ───────────────────────────────────────────────────────

class _RecipientState:
    __slots__ = (
        "arrivals",           # deque of (ts, sender_domain, is_pattern_match)
        "seen_domains",       # set of all sender domains ever seen (capped)
        "under_attack_until", # monotonic ts when hold expires (0 = not active)
        "last_alerted",       # last Slack alert ts
    )

    def __init__(self):
        self.arrivals:           deque = deque()
        self.seen_domains:       set   = set()
        self.under_attack_until: float = 0.0
        self.last_alerted:       float = 0.0


_lock  = threading.Lock()
_state: dict[str, _RecipientState] = {}


def _get_or_create(rcpt: str) -> _RecipientState:
    if rcpt not in _state:
        _state[rcpt] = _RecipientState()
    return _state[rcpt]


def _prune(arrivals: deque, now: float) -> None:
    while arrivals and arrivals[0][0] < now - WINDOW_SECS:
        arrivals.popleft()


# ── Public API ────────────────────────────────────────────────────────────────

def record(rcpt: str, sender_email: str, subject: str) -> tuple[bool, bool]:
    """
    Record an arriving email and evaluate the bombing score.

    Returns (is_under_attack, newly_detected).
      is_under_attack  — caller should adjust routing
      newly_detected   — caller should log; Slack alert fires internally
    """
    if not rcpt:
        return False, False

    rcpt       = rcpt.strip().lower()
    domain     = _sender_domain(sender_email)
    is_pattern = _matches_subscription_pattern(subject or "")
    now        = time.monotonic()

    with _lock:
        st = _get_or_create(rcpt)
        _prune(st.arrivals, now)

        # Already under attack — don't re-evaluate, just report
        if now < st.under_attack_until:
            st.arrivals.append((now, domain, is_pattern))
            if len(st.seen_domains) < MAX_SEEN_DOMAINS:
                st.seen_domains.add(domain)
            return True, False

        # Record this email
        st.arrivals.append((now, domain, is_pattern))
        if len(st.seen_domains) < MAX_SEEN_DOMAINS:
            st.seen_domains.add(domain)

        # ── Early velocity path ───────────────────────────────────────────────
        vel_emails  = [e for e in st.arrivals if e[0] >= now - VELOCITY_WINDOW]
        vel_pattern = sum(1 for _, _, p in vel_emails if p)
        if vel_pattern >= VELOCITY_THRESHOLD:
            return _trigger(st, rcpt, len(vel_emails), 1.0, 0.0, now, "velocity")

        # ── Full scoring path ─────────────────────────────────────────────────
        window = list(st.arrivals)
        n      = len(window)

        if n < VOLUME_THRESHOLD:
            return False, False

        pattern_count  = sum(1 for _, _, p in window if p)
        pattern_ratio  = pattern_count / n

        window_domains     = [d for _, d, _ in window]
        pre_window_seen    = st.seen_domains - set(window_domains)
        new_domain_count   = sum(1 for d in window_domains if d not in pre_window_seen)
        diversity_ratio    = new_domain_count / n

        score = _compute_score(n, pattern_ratio, diversity_ratio, len(st.seen_domains))

        if score < DETECT_SCORE_THRESHOLD:
            return False, False

        return _trigger(st, rcpt, n, pattern_ratio, diversity_ratio, now,
                        f"score={score}")


def _trigger(st: _RecipientState, rcpt: str, count: int,
             pattern_ratio: float, diversity_ratio: float,
             now: float, trigger: str) -> tuple[bool, bool]:
    st.under_attack_until = now + HOLD_MINUTES * 60
    logger.warning(
        "inbox_bombing_detected",
        rcpt=rcpt, emails=count, trigger=trigger,
        pattern_pct=round(pattern_ratio * 100),
        diversity_pct=round(diversity_ratio * 100),
        hold_mins=HOLD_MINUTES,
    )
    if now - st.last_alerted > ALERT_SUPPRESS_SECS:
        st.last_alerted = now
        _alert_async(rcpt, count, pattern_ratio, diversity_ratio, trigger)
    return True, True


def is_under_attack(rcpt: str) -> bool:
    if not rcpt:
        return False
    rcpt = rcpt.strip().lower()
    now  = time.monotonic()
    with _lock:
        st = _state.get(rcpt)
        return bool(st and now < st.under_attack_until)


def clear_attack(rcpt: str) -> None:
    rcpt = rcpt.strip().lower()
    with _lock:
        st = _state.get(rcpt)
        if st:
            st.under_attack_until = 0.0
    logger.info("inbox_bombing_cleared", rcpt=rcpt)


def active_attacks() -> list[dict]:
    now = time.monotonic()
    out = []
    with _lock:
        for rcpt, st in _state.items():
            if now < st.under_attack_until:
                window = list(st.arrivals)
                _prune(deque(window), now)
                secs_left = int(st.under_attack_until - now)
                out.append({
                    "rcpt":                 rcpt,
                    "emails_in_window":     len(window),
                    "hold_expires_in_secs": secs_left,
                    "hold_expires_in_mins": round(secs_left / 60, 1),
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
                "window_secs":             WINDOW_SECS,
                "volume_threshold":        VOLUME_THRESHOLD,
                "diversity_ratio":         DIVERSITY_RATIO,
                "pattern_ratio":           PATTERN_RATIO,
                "detect_score_threshold":  DETECT_SCORE_THRESHOLD,
                "hold_minutes":            HOLD_MINUTES,
                "velocity_window_secs":    VELOCITY_WINDOW,
                "velocity_threshold":      VELOCITY_THRESHOLD,
                "cold_start_min_history":  COLD_START_MIN_HISTORY,
            },
        }


def _alert_async(rcpt: str, count: int, pattern_ratio: float,
                 diversity_ratio: float, trigger: str) -> None:
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
                    {"type": "mrkdwn", "text": f"*Emails in window:*\n{count}"},
                    {"type": "mrkdwn", "text": f"*Trigger:*\n`{trigger}`"},
                    {"type": "mrkdwn", "text": f"*Pattern match:*\n{round(pattern_ratio*100)}%"},
                    {"type": "mrkdwn", "text": f"*New domains:*\n{round(diversity_ratio*100)}%"},
                    {"type": "mrkdwn", "text": f"*Hold duration:*\n{HOLD_MINUTES} minutes"},
                ]},
                {"type": "section", "text": {"type": "mrkdwn",
                    "text": (
                        f"⚠️ *Subscription bomb in progress.*\n"
                        f"• Subscription noise → held for SOC review\n"
                        f"• OTP/password-reset/bank emails → delivered immediately\n"
                        f"• _SOC: bulk-approve clean emails, clear hold when done_"
                    )}},
            ]}
            _hx.post(webhook, json=payload, timeout=10)
        except Exception as exc:
            logger.warning("bombing_alert_err", error=str(exc))

    _thr.Thread(target=_send, daemon=True, name="bombing-slack").start()
