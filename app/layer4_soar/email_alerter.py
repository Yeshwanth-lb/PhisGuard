"""Layer 4 - SMTP email alerter."""
import asyncio
import smtplib
import ssl
from email.message import EmailMessage

import certifi

import structlog

logger = structlog.get_logger()


def _build_email(doc, sender_addr, recipient):
    a = doc.get("parsed") or {}
    v = doc.get("verdict", "x")
    c = doc.get("confidence", 0.0)
    bl = doc.get("blocked_at") or "n/a"
    snd = a.get("from_header") or "?"
    sub = a.get("subject") or "(none)"
    links = (a.get("urls") or [])[:5]

    msg = EmailMessage()
    msg["From"] = sender_addr
    msg["To"] = recipient
    msg["Subject"] = "[PhishGuard SOC ALERT] " + v.upper() + " detected — " + sub[:60]

    L = [
        "=" * 55,
        "  PHISHGUARD — SOC SECURITY ALERT",
        "  This is an automated notification for the security team.",
        "  The phishing email was BLOCKED — it did NOT reach the recipient.",
        "=" * 55,
        "",
        "VERDICT    : " + v.upper() + " (" + str(round(c * 100)) + "% confidence)",
        "BLOCKED AT : " + str(bl),
        "",
        "PHISHING EMAIL DETAILS (this was intercepted):",
        "  Sender   : " + snd,
        "  Subject  : " + sub,
        "  Links    : " + str(len(links)),
    ]
    if links:
        L.append("  Top URLs : " + ", ".join(links[:3]))
    l3 = doc.get("l3") or {}
    if l3 and l3.get("final_url"):
        L.append("")
        L.append("SANDBOX DETONATION:")
        L.append("  Final URL: " + (l3.get("final_url") or "n/a"))
        L.append("  Title    : " + (l3.get("title") or "n/a"))
    L.extend([
        "",
        "Review full report: http://localhost:8000 → Reports tab",
        "",
        "=" * 55,
        "PhishGuard automated security system",
        "DO NOT REPLY to this email.",
    ])
    msg.set_content(chr(10).join(L))
    return msg


def _send_sync(host, port, user, pwd, use_tls, msg):
    if use_tls:
        ctx = ssl.create_default_context(cafile=certifi.where())
        with smtplib.SMTP(host, port, timeout=15) as s:
            s.starttls(context=ctx)
            if user:
                s.login(user, pwd)
            s.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=15) as s:
            if user:
                s.login(user, pwd)
            s.send_message(msg)


def _cfg(s):
    g = lambda k, d: getattr(s, k, d) or d
    return {
        "host": g("alert_smtp_host", ""),
        "port": int(g("alert_smtp_port", 587) or 587),
        "user": g("alert_smtp_user", ""),
        "pwd": g("alert_smtp_password", ""),
        "tls": bool(g("alert_smtp_use_tls", True)),
        "to": g("alert_email_to", ""),
        "frm": g("alert_email_from", ""),
    }


async def send_alert_email(doc, settings):
    cfg = _cfg(settings)
    if not (cfg["host"] and cfg["to"] and cfg["frm"]):
        return False
    v = doc.get("verdict", "")
    if v not in ("phishing", "suspicious"):
        return False
    try:
        msg = _build_email(doc, cfg["frm"], cfg["to"])
        await asyncio.to_thread(_send_sync, cfg["host"], cfg["port"], cfg["user"], cfg["pwd"], cfg["tls"], msg)
        logger.info("alert_email_sent", to=cfg["to"], verdict=v)
        return True
    except Exception as exc:
        logger.warning("alert_email_error", error=str(exc))
        return False


async def probe_email(settings):
    cfg = _cfg(settings)
    if not (cfg["host"] and cfg["to"] and cfg["frm"]):
        return {"configured": False, "reachable": False, "reason": "not_configured"}

    def _probe():
        if cfg["tls"]:
            ctx = ssl.create_default_context(cafile=certifi.where())
            with smtplib.SMTP(cfg["host"], cfg["port"], timeout=10) as s:
                s.starttls(context=ctx)
                if cfg["user"]:
                    s.login(cfg["user"], cfg["pwd"])
                s.noop()
        else:
            with smtplib.SMTP(cfg["host"], cfg["port"], timeout=10) as s:
                if cfg["user"]:
                    s.login(cfg["user"], cfg["pwd"])
                s.noop()
        return True

    try:
        await asyncio.to_thread(_probe)
        return {"configured": True, "reachable": True, "host": cfg["host"], "port": cfg["port"]}
    except Exception as exc:
        return {"configured": True, "reachable": False, "error": str(exc)}
