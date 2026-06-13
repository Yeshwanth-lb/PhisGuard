"""Layer 7 - SMTP receiver: accepts forwarded emails."""
import structlog
from typing import Optional

logger = structlog.get_logger()


class PhishGuardSMTPHandler:

    def __init__(self, analyze_fn, settings):
        self.analyze_fn = analyze_fn
        self.settings = settings

    async def handle_DATA(self, server, session, envelope) -> str:
        raw_bytes = envelope.content
        peer = session.peer
        logger.info("smtp_received", peer=str(peer), size=len(raw_bytes))
        try:
            result = await self.analyze_fn(raw_bytes, self.settings)
            verdict = result.get("verdict", "unknown")
            logger.info("smtp_verdict", verdict=verdict)
        except Exception as exc:
            logger.warning("smtp_err", error=str(exc))
        return "250 OK"


async def start_smtp_server(analyze_fn, settings) -> Optional[object]:
    try:
        from aiosmtpd.controller import Controller  # type: ignore
        hdlr = PhishGuardSMTPHandler(analyze_fn, settings)
        ctrl = Controller(
            hdlr,
            hostname=settings.smtp_listen_host,
            port=settings.smtp_listen_port,
        )
        ctrl.start()
        logger.info("smtp_started", host=settings.smtp_listen_host, port=settings.smtp_listen_port)
        return ctrl
    except Exception as exc:
        logger.warning("smtp_start_failed", error=str(exc))
        return None
