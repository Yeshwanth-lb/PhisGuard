import time
from typing import Dict, Any, List
from app.config import settings
import structlog

logger = structlog.get_logger()

async def run_pipeline(email_id, parsed, extracted_links):
    start = time.time()
    logger.info("pipeline_start", email_id=email_id)
    elapsed = int((time.time() - start) * 1000)
    return {"verdict": "delivered", "confidence": 0.0, "route": "skeleton", "processing_time_ms": elapsed}
