"""ThreatLens Slack Alerts — smart escalations for critical threat intelligence.

Three triggers (in order of priority):

  Trigger 1 — Critical surface zone targeted
    Fires when a cluster is mapped to ground_station_ingress or ntn_5g_core.
    These are Skylo's most sensitive attack surfaces. Any attacker targeting
    them gets an immediate escalation regardless of confidence level.

  Trigger 2 — Confirmed threat actor match
    Fires when MISP returns a hard IoC match → confidence=confirmed.
    This means a known threat actor's infrastructure matches the cluster.

  Trigger 3 — New high-severity cluster (severity=critical/high + no prior alert)
    Fires for any new critical/high cluster so the SOC knows immediately.

Uses Slack Block Kit for rich formatted messages.
Reuses SLACK_WEBHOOK_URL from the main settings.
"""
from __future__ import annotations

import os

import httpx
import structlog

from app.threatlens.models import AdversaryProfile, ActorCluster

logger = structlog.get_logger()

# Surface zones that always warrant escalation
_CRITICAL_ZONES = {"ground_station_ingress", "ntn_5g_core"}
# High-priority zones — alert only if severity is high/critical
_HIGH_ZONES = {"gcp_infra", "supply_chain"}

_ZONE_LABELS = {
    "ground_station_ingress": "Ground Station Ingress 📡",
    "ntn_5g_core":            "NTN / 5G Core 🛰",
    "gcp_infra":              "GCP Infrastructure ☁️",
    "supply_chain":           "MNO / Supply Chain 🔗",
    "corporate_it":           "Corporate IT 🏢",
}

_SEV_EMOJI = {"critical": "🚨", "high": "⚠️", "medium": "🔶", "low": "ℹ️"}
_CONF_EMOJI = {"confirmed": "✅", "high": "🔵", "moderate": "🟡", "low": "⬜", "speculative": "⬜"}


def _should_alert(profile: AdversaryProfile) -> tuple[bool, str]:
    """Return (should_alert, reason). Called once per profiled cluster."""
    zones = set(profile.surface_zones or [])

    # Trigger 1 — critical Skylo surface
    critical_hit = zones & _CRITICAL_ZONES
    if critical_hit:
        return True, f"critical_surface:{','.join(critical_hit)}"

    # Trigger 2 — confirmed match in MISP/feed
    if profile.confidence == "confirmed":
        return True, "confirmed_threat_actor"

    # Trigger 3 — high/critical severity cluster on high-priority zone
    high_hit = zones & _HIGH_ZONES
    if high_hit and profile.severity in ("critical", "high"):
        return True, f"high_severity_zone:{','.join(high_hit)}"

    return False, ""


def _build_alert(
    cluster: ActorCluster,
    profile: AdversaryProfile,
    reason: str,
    dashboard_url: str = "http://localhost:8000",
) -> dict:
    """Build a Slack Block Kit payload for a ThreatLens escalation."""
    sev_emoji = _SEV_EMOJI.get(profile.severity, "⚠️")
    conf_emoji = _CONF_EMOJI.get(profile.confidence, "⬜")
    zones = profile.surface_zones or []
    zone_text = " · ".join(_ZONE_LABELS.get(z, z) for z in zones if z != "unmapped") or "unmapped"
    ttps_text = " · ".join(t.attack_id for t in profile.ttps[:4]) or "none mapped"
    domains_text = " · ".join(cluster.iocs.domains[:3]) or "unknown"

    # Header changes based on reason
    if "critical_surface" in reason:
        header = f"{sev_emoji} ThreatLens: Critical Surface Targeted"
        alert_context = f"*Skylo attack surface under active targeting:*\n`{zone_text}`"
    elif reason == "confirmed_threat_actor":
        header = f"🎯 ThreatLens: Confirmed Threat Actor Match"
        alert_context = f"*MISP confirmed a known threat actor IoC in this cluster.*\nConfidence: `confirmed` via hard feed match."
    else:
        header = f"{sev_emoji} ThreatLens: High-Severity Cluster Detected"
        alert_context = f"*High-severity activity on Skylo infrastructure zone:*\n`{zone_text}`"

    return {
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": header, "emoji": True},
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": alert_context},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severity*\n{sev_emoji} `{profile.severity.upper()}`"},
                    {"type": "mrkdwn", "text": f"*Confidence*\n{conf_emoji} `{profile.confidence}`"},
                    {"type": "mrkdwn", "text": f"*Intent*\n{profile.assessed_intent[:60]}"},
                    {"type": "mrkdwn", "text": f"*Campaign size*\n{len(cluster.member_scan_ids)} emails"},
                    {"type": "mrkdwn", "text": f"*ATT&CK Techniques*\n`{ttps_text}`"},
                    {"type": "mrkdwn", "text": f"*Observed domains*\n`{domains_text}`"},
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"_{profile.summary[:200] if profile.summary else 'No summary available.'}_",
                },
            },
            {"type": "divider"},
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "View in Dashboard →", "emoji": True},
                        "url": f"{dashboard_url}",
                        "style": "primary",
                    }
                ],
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"PhishGuard ThreatLens · Cluster `{cluster.id[:8]}` · "
                                f"Profile `{profile.id[:8]}` · Suspected APT: {profile.suspected_apt or 'none attributed'}",
                    }
                ],
            },
        ]
    }


async def alert_if_critical(
    cluster: ActorCluster,
    profile: AdversaryProfile,
    webhook_url: str | None = None,
    dashboard_url: str = "http://localhost:8000",
) -> bool:
    """Check thresholds and send a Slack alert if warranted.

    Returns True if an alert was sent.
    """
    if not webhook_url:
        webhook_url = os.environ.get("SLACK_WEBHOOK_URL", "")
    if not webhook_url:
        return False

    should, reason = _should_alert(profile)
    if not should:
        return False

    payload = _build_alert(cluster, profile, reason, dashboard_url)
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(webhook_url, json=payload)
            resp.raise_for_status()
        logger.info(
            "threatlens_slack_alert_sent",
            cluster=cluster.id[:8],
            reason=reason,
            severity=profile.severity,
            confidence=profile.confidence,
            zones=profile.surface_zones,
        )
        return True
    except Exception as exc:
        logger.warning("threatlens_slack_alert_failed", error=str(exc)[:100])
        return False


async def send_cycle_summary(
    clusters_processed: int,
    profiles_written: int,
    confirmed_count: int,
    critical_zones_count: int,
    webhook_url: str | None = None,
) -> None:
    """Send a brief cycle summary to Slack if anything notable happened."""
    if not webhook_url:
        webhook_url = os.environ.get("SLACK_WEBHOOK_URL", "")
    if not webhook_url:
        return
    if confirmed_count == 0 and critical_zones_count == 0:
        return  # Nothing notable — skip summary

    text = (
        f"🔍 *ThreatLens cycle complete* — {profiles_written} profiles updated\n"
        f"> {confirmed_count} confirmed threat actor matches · "
        f"{critical_zones_count} critical surface zone alerts sent"
    )
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(webhook_url, json={"text": text})
    except Exception:
        pass
