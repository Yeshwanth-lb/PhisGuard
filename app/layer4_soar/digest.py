"""Weekly threat digest — builds a Slack Block Kit summary and posts it.

Covers:
  • Scan volume breakdown (phishing / suspicious / clean)
  • Top attacker domains
  • Top NLP attack intents
  • Active campaigns detected
  • Quick-link back to the dashboard

Can be triggered manually via POST /api/digest/send or runs automatically
on a configurable schedule (default: every Monday at 09:00 local time).
"""
import json
import re
import sqlite3
import time
from collections import defaultdict
from datetime import datetime

import httpx
import structlog

from .campaign_detector import detect_campaigns

logger = structlog.get_logger()


def _sender_domain(sender: str) -> str:
    if not sender:
        return ""
    m = re.search(r"@([\w.\-]+)", sender)
    return m.group(1).lower() if m else ""


def _get_stats(db_path: str, since: float) -> dict:
    conn = sqlite3.connect(db_path)
    stats: dict = {}
    for verdict in ("phishing", "suspicious", "clean"):
        row = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE verdict=? AND ts>=? AND deleted=0",
            (verdict, since),
        ).fetchone()
        stats[verdict] = row[0] if row else 0

    # Top attacker domains (phishing emails)
    rows = conn.execute(
        """SELECT sender, COUNT(*) AS cnt
           FROM scans
           WHERE verdict='phishing' AND ts>=? AND deleted=0 AND sender IS NOT NULL AND sender != ''
           GROUP BY sender ORDER BY cnt DESC LIMIT 5""",
        (since,),
    ).fetchall()
    stats["top_senders"] = [(r[0], r[1]) for r in rows]

    # Top NLP intents from data_json
    intent_counts: dict[str, int] = defaultdict(int)
    rows2 = conn.execute(
        "SELECT data_json FROM scans WHERE verdict IN ('phishing','suspicious') AND ts>=? AND deleted=0",
        (since,),
    ).fetchall()
    for (data_json,) in rows2:
        try:
            data = json.loads(data_json) if data_json else {}
            intent = (data.get("l2") or {}).get("engines", {}).get("nlp", {}).get("intent", "")
            if intent and intent not in ("clean", "unknown", ""):
                intent_counts[intent] += 1
        except Exception:
            pass
    stats["top_intents"] = sorted(intent_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    conn.close()
    stats["total"] = stats["phishing"] + stats["suspicious"] + stats["clean"]
    return stats


def _build_blocks(stats: dict, campaigns: list, period: str, dashboard_url: str) -> list:
    """Build Slack Block Kit blocks for the digest."""
    total      = stats["total"]
    phish      = stats["phishing"]
    sus        = stats["suspicious"]
    clean      = stats["clean"]
    phish_pct  = round(phish / total * 100, 1) if total else 0
    sus_pct    = round(sus   / total * 100, 1) if total else 0
    clean_pct  = round(clean / total * 100, 1) if total else 0

    sev_emoji  = {"critical": "🔥", "high": "🔴", "medium": "🟡"}
    type_emoji = {"domain_pattern": "🌐", "intent": "🎯"}

    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": "🛡️ PhishGuard Weekly Threat Digest"}},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": f"Period: *{period}*"}]},
        {"type": "divider"},

        # ── Scan volume ─────────────────────────────────────────────────────
        {"type": "section", "text": {"type": "mrkdwn", "text": "*📊 Scan Summary*"}},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Total scanned*\n{total:,}"},
            {"type": "mrkdwn", "text": f"*🔴 Phishing blocked*\n{phish:,} ({phish_pct}%)"},
            {"type": "mrkdwn", "text": f"*🟡 Held for review*\n{sus:,} ({sus_pct}%)"},
            {"type": "mrkdwn", "text": f"*✅ Clean delivered*\n{clean:,} ({clean_pct}%)"},
        ]},
        {"type": "divider"},
    ]

    # ── Top attacker domains ──────────────────────────────────────────────
    if stats["top_senders"]:
        lines = "\n".join(
            f"{i+1}. `{s}` — {c} attack{'s' if c>1 else ''}"
            for i, (s, c) in enumerate(stats["top_senders"])
        )
        blocks.append({"type": "section", "text": {"type": "mrkdwn",
            "text": f"*🌐 Top Attacker Addresses*\n{lines}"}})
        blocks.append({"type": "divider"})

    # ── Top attack types ──────────────────────────────────────────────────
    if stats["top_intents"]:
        lines = "\n".join(
            f"{i+1}. {intent.replace('_',' ').title()} — {cnt} email{'s' if cnt>1 else ''}"
            for i, (intent, cnt) in enumerate(stats["top_intents"])
        )
        blocks.append({"type": "section", "text": {"type": "mrkdwn",
            "text": f"*🎯 Top Attack Types*\n{lines}"}})
        blocks.append({"type": "divider"})

    # ── Active campaigns ──────────────────────────────────────────────────
    active = [c for c in campaigns if c.get("active")]
    if active:
        cam_lines = []
        for c in active[:5]:
            emoji = sev_emoji.get(c["severity"], "⚠️")
            te    = type_emoji.get(c["type"], "📌")
            span  = _time_span(c["first_seen"], c["last_seen"])
            cam_lines.append(
                f"{emoji} {te} *{c['name']}* — {c['email_count']} emails over {span}"
            )
        blocks.append({"type": "section", "text": {"type": "mrkdwn",
            "text": "*🚨 Active Campaigns*\n" + "\n".join(cam_lines)}})
        blocks.append({"type": "divider"})
    elif campaigns:
        blocks.append({"type": "section", "text": {"type": "mrkdwn",
            "text": f"*📌 Campaigns*\n{len(campaigns)} campaign(s) detected (no active in last 24h)"}})
        blocks.append({"type": "divider"})
    else:
        blocks.append({"type": "section", "text": {"type": "mrkdwn",
            "text": "*📌 Campaigns*\nNo coordinated campaigns detected this week."}})
        blocks.append({"type": "divider"})

    # ── Footer ────────────────────────────────────────────────────────────
    blocks.append({"type": "context", "elements": [
        {"type": "mrkdwn",
         "text": f"_Generated by PhishGuard v1.5 | <{dashboard_url}|Open Dashboard>_"},
    ]})

    return blocks


def _time_span(first_ts: float, last_ts: float) -> str:
    days = max(1, int((last_ts - first_ts) / 86400) + 1)
    return f"{days} day{'s' if days > 1 else ''}"


async def send_digest(
    db_path: str,
    slack_webhook_url: str,
    window_days: int = 7,
    dashboard_url: str = "http://localhost:8000",
) -> dict:
    """Build and post the weekly digest to Slack. Returns status dict."""
    if not slack_webhook_url:
        logger.warning("digest_no_webhook")
        return {"ok": False, "error": "SLACK_WEBHOOK_URL not configured"}

    since  = time.time() - window_days * 86400
    now_dt = datetime.now()
    since_dt = datetime.fromtimestamp(since)
    period = f"{since_dt.strftime('%b %d')} – {now_dt.strftime('%b %d, %Y')}"

    stats     = _get_stats(db_path, since)
    campaigns = detect_campaigns(db_path, window_days=window_days)
    blocks    = _build_blocks(stats, campaigns, period, dashboard_url)

    payload = {"blocks": blocks}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(slack_webhook_url, json=payload)
        if resp.status_code == 200 and resp.text == "ok":
            logger.info("digest_sent", period=period, total=stats["total"])
            return {"ok": True, "period": period, "stats": stats,
                    "campaigns": len(campaigns)}
        else:
            logger.warning("digest_slack_err", status=resp.status_code, body=resp.text[:200])
            return {"ok": False, "error": f"Slack returned {resp.status_code}: {resp.text[:100]}"}
    except Exception as exc:
        logger.warning("digest_send_err", error=str(exc))
        return {"ok": False, "error": str(exc)}


def start_digest_scheduler(settings) -> None:
    """Start a daemon thread that sends the digest every Monday at 09:00."""
    import threading

    slack_url    = getattr(settings, "slack_webhook_url", "") or ""
    db_path      = getattr(settings, "phishguard_db_path", "data/phishguard.db") or "data/phishguard.db"
    dash_url     = getattr(settings, "dashboard_url", "http://localhost:8000") or "http://localhost:8000"

    if not slack_url:
        logger.info("digest_scheduler_skipped", reason="no_slack_webhook")
        return

    def _loop():
        import asyncio
        last_sent_week = -1
        while True:
            now = datetime.now()
            week_num = now.isocalendar()[1]
            # Fire on Monday (weekday 0) between 09:00–09:29 — once per week
            if now.weekday() == 0 and now.hour == 9 and week_num != last_sent_week:
                try:
                    result = asyncio.run(send_digest(db_path, slack_url, dashboard_url=dash_url))
                    if result.get("ok"):
                        last_sent_week = week_num
                        logger.info("digest_scheduler_sent", week=week_num)
                except Exception as exc:
                    logger.warning("digest_scheduler_err", error=str(exc))
            time.sleep(1800)  # check every 30 minutes

    t = threading.Thread(target=_loop, daemon=True, name="digest-scheduler")
    t.start()
    logger.info("digest_scheduler_started", schedule="monday_09:00")
