"""Layer 4 - SOAR orchestrator: fan-out to all threat intel exporters."""
import asyncio

import structlog

from . import denylist
from .email_alerter import send_alert_email
from .es_exporter import export_to_es
from .jira_exporter import export_to_jira
from .misp_exporter import export_to_misp
from .opencti_exporter import export_to_opencti
from .slack_notifier import notify_slack

logger = structlog.get_logger()


async def _auto_denylist(verdict_doc: dict, settings) -> dict:
    try:
        added = denylist.auto_populate_from_verdict(verdict_doc)
        if added:
            logger.info("denylist_auto_added", entries=[f"{k}:{v}" for k, v in added])
        return {"added": [f"{k}:{v}" for k, v in added]}
    except Exception as exc:
        logger.warning("denylist_err", error=str(exc))
        return {"error": str(exc)}


async def run_soar(verdict_doc: dict, settings) -> dict:
    """Fan-out verdict to all SOAR integrations concurrently."""
    tasks = [
        export_to_es(verdict_doc, settings),
        notify_slack(verdict_doc, settings),
        export_to_misp(verdict_doc, settings),
        export_to_opencti(verdict_doc, settings),
        export_to_jira(verdict_doc, settings),
        send_alert_email(verdict_doc, settings),
        _auto_denylist(verdict_doc, settings),
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    labels = ["es", "slack", "misp", "opencti", "jira", "email", "denylist"]
    outcome = {}
    for lbl, res in zip(labels, results):
        if isinstance(res, Exception):
            logger.warning("soar_fan_out_err", target=lbl, error=str(res))
            outcome[lbl] = False
        elif isinstance(res, dict):
            # Preserve rich result dicts (MISP returns export metadata, denylist returns added list)
            outcome[lbl] = res
        else:
            outcome[lbl] = bool(res)

    # Surface MISP event ID in the top-level verdict doc so ES and Slack can reference it
    misp_result = outcome.get("misp")
    if isinstance(misp_result, dict) and misp_result.get("misp_event_id"):
        verdict_doc["misp_event_id"] = misp_result["misp_event_id"]
        verdict_doc["misp_export"] = misp_result

    logger.info("soar_complete", outcome={k: (v if not isinstance(v, dict) else v.get("export_status", True)) for k, v in outcome.items()})
    return outcome
