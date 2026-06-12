import time
import uuid
import structlog
from fastapi import FastAPI, UploadFile, Form, HTTPException, Depends
from fastapi.security import HTTPBearer
from typing import Optional

from app.config import settings
from app.models import AnalyzeResponse, Verdict
from app.parser.email_parser import parse_email
from app.parser.url_extractor import extract_urls, resolve_shortened_urls

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ],
    logger_factory=structlog.PrintLoggerFactory(),
)

logger = structlog.get_logger()
app = FastAPI(title="PhishGuard", version="1.5.0")
_bearer = HTTPBearer(auto_error=False)


def verify_api_key(token=Depends(HTTPBearer(auto_error=False))):
    key = token.token if hasattr(token, "token") else (token.cred if hasattr(token, "cred") else "")
    if not token or getattr(token, "scheme", "").lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid API key")
    return token


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "elasticsearch": "disconnected",
        "virustotal_api": "ok" if settings.virustotal_api_key else "unconfigured",
        "abuseipdb_api": "ok" if settings.abuseipdb_api_key else "unconfigured",
        "urlhaus_api": "ok",
        "phishtank_api": "ok" if settings.phishtank_api_key else "unconfigured",
        "misp_api": "ok" if settings.misp_api_key else "unconfigured",
        "openai_api": "ok" if settings.openai_api_key else "unconfigured",
        "opencti": "disconnected",
        "docker_pool": "ok",
        "layer2_engines": {"nlp": "ok", "behavioral": "ok", "structural": "ok"},
    }


@app.post("/analyze")
async def analyze_email(email_file=None, raw_email=None):
    start = time.time()
    email_id = str(uuid.uuid4())
    if email_file:
        raw_bytes = await email_file.read()
    elif raw_email:
        raw_bytes = raw_email.encode("utf-8")
    else:
        raise HTTPException(status_code=400, detail="Provide email_file or raw_email")
    parsed = parse_email(raw_bytes)
    if not parsed:
        raise HTTPException(status_code=422, detail="Failed to parse email")
    extracted = extract_urls(
        body_text=parsed.get("body_text", "") or "",
        body_html=parsed.get("body_html", "") or "",
    )
    extracted = await resolve_shortened_urls(extracted)
    elapsed_ms = int((time.time() - start) * 1000)
    logger.info("email_parsed", email_id=email_id, url_count=len(extracted),
        attachment_count=len(parsed.get("attachments", [])), elapsed_ms=elapsed_ms)
    return {"email_id": email_id, "verdict": "delivered",
            "confidence": 0.0, "processing_time_ms": elapsed_ms}


@app.get("/report/{email_id}")
async def get_report(email_id: str):
    raise HTTPException(status_code=501, detail="Phase 4 not yet built")


@app.get("/quarantine")
async def get_quarantine(page: int = 1, limit: int = 50):
    raise HTTPException(status_code=501, detail="Phase 4 not yet built")
