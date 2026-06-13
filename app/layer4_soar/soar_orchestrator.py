"""Layer 4 - SOAR orchestrator: fan-out to all threat intel exporters."""
import asyncio
import structlog
from .es_exporter import export_to_es
from .slack_notifier import notify_slack
from .misp_exporter import export_to_misp
from .opencti_exporter import export_to_opencti
logger = structlog.get_logger()


async def run_soar(verdict_doc: dict, settings) -> dict:
    """Fan-out verdict to all SOAR integrations concurrently."""
    tasks = [
        export_to_es(verdict_doc, settings),
        notify_slack(verdict_doc, settings),
        export_to_misp(verdict_doc, settings),
        export_to_opencti(verdict_doc, settings),
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    labels = ["es", "slack", "misp", "opencti"]
    outcome = {}
    for lbl, res in zip(labels, results):
        if isinstance(res, Exception):
            logger.warning("soar_fan_out_err", target=lbl, error=str(res))
            outcome[lbl] = False
        else:
            outcome[lbl] = bool(res)
    logger.info("soar_complete", outcome=outcome)
    return outcome
