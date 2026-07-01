import json
import os
import time
import uuid

import structlog
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

from app import storage
from app.config import settings
from app.pipeline import analyze_email as run_pipeline
from app.security.audit import AuditMiddleware, read_audit_log
from app.security.auth import create_token_pair, require_auth
from app.security.rate_limiter import get_rate_limiter
from app.security.rbac import require_permission, require_admin

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt='iso'),
        structlog.processors.JSONRenderer(),
    ],
    logger_factory=structlog.PrintLoggerFactory(),
)

logger = structlog.get_logger()

from contextlib import asynccontextmanager as _acm


@_acm
async def _lifespan(app):
    # Fail fast if the JWT signing secret is unset/default — otherwise anyone could
    # forge an admin token. (Set ALLOW_INSECURE_JWT_SECRET=true for local dev.)
    from app.security.auth import assert_secure_secret
    assert_secure_secret()
    # Auto-start SMTP receiver if enabled
    from app.layer7_gmail.smtp_receiver import start_smtp_server as _sss
    from app.pipeline import analyze_email as _aeb
    _smtp_ctrl = None
    if getattr(settings, "smtp_listen_port", 0):
        try:
            _smtp_ctrl = await _sss(_aeb, settings)
        except Exception as _e:
            logger.warning("smtp_autostart_failed", error=str(_e))
    # Start the bombing-buffer release worker (releases Tier-2/3 mail past the window)
    try:
        from app.layer7_gmail.smtp_receiver import start_release_worker as _srw
        _srw(settings)
    except Exception as _e:
        logger.warning("bombing_release_worker_start_failed", error=str(_e))
    # Auto-start pull subscriber if enabled
    from app.layer7_gmail.pubsub_watcher import start_pull_subscriber as _sps
    from app.layer7_gmail.pubsub_watcher import stop_pull_subscriber as _stp
    if getattr(settings, "gmail_enable_pull_subscriber", False):
        try:
            _sps(_aeb, settings)
        except Exception as _e:
            logger.warning("pull_autostart_failed", error=str(_e))
    # Start weekly digest scheduler
    try:
        from app.layer4_soar.digest import start_digest_scheduler
        start_digest_scheduler(settings)
    except Exception as _e:
        logger.warning("digest_scheduler_start_failed", error=str(_e))
    # Initialise ThreatLens tables (idempotent — safe on every startup)
    try:
        from app.threatlens.store import init_db as _tl_init_db
        _tl_init_db()
    except Exception as _e:
        logger.warning("threatlens_init_db_failed", error=str(_e))
    # Start ThreatLens scheduler (no-op when INTEL_ENABLED=false)
    try:
        from app.threatlens.scheduler import start_scheduler as _start_tl
        _start_tl()
    except Exception as _e:
        logger.warning("threatlens_scheduler_start_failed", error=str(_e))
    # Auto-bootstrap ML model on first startup
    if getattr(settings, "ml_bootstrap_on_startup", True):
        try:
            import threading as _thr

            from app.layer5_ml.bootstrap import bootstrap_and_train as _bat
            _ml_dir = getattr(settings, "ml_local_data_dir", "data/training")
            _ml_out = getattr(settings, "ml_model_path", "data/model.pkl")
            _thr.Thread(target=_bat, args=(_ml_dir, _ml_out), daemon=True, name="ml-bootstrap").start()
        except Exception as _e:
            logger.warning("ml_bootstrap_failed", error=str(_e))
    yield
    # Shutdown
    if _smtp_ctrl:
        try:
            _smtp_ctrl.stop()
        except Exception:
            pass
    _stp()

app = FastAPI(title='PhishGuard', version='1.5.0', docs_url='/api/docs', lifespan=_lifespan)
_rate_limit = get_rate_limiter(limit=120, window=60)

_cors_origins = [o.strip() for o in getattr(settings, 'cors_allow_origins', '').split(',') if o.strip()] \
    or ['http://localhost:8000', 'http://127.0.0.1:8000']
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,            # no wildcard with credentials
    allow_credentials=True,
    allow_methods=['GET', 'POST', 'DELETE', 'PATCH', 'OPTIONS'],
    allow_headers=['Authorization', 'Content-Type'],
)

app.add_middleware(AuditMiddleware)

# ---- Prometheus metrics (gated — only if library installed) ----
try:
    from prometheus_fastapi_instrumentator import Instrumentator as _PFI
    _PFI().instrument(app).expose(app, endpoint="/metrics", include_in_schema=False)
    logger.info("prometheus_metrics_enabled", endpoint="/metrics")
except ImportError:
    pass

# ---- OpenTelemetry tracing (gated — only if OTEL_EXPORTER_OTLP_ENDPOINT set) ----
_otel_endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "")
if _otel_endpoint:
    try:
        from opentelemetry import trace as _otel_trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter as _OTLPExporter
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor as _FAI
        from opentelemetry.sdk.resources import Resource as _Resource
        from opentelemetry.sdk.trace import TracerProvider as _TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor as _BatchProcessor

        _resource = _Resource.create({"service.name": "phishguard", "service.version": "1.5.0"})
        _provider = _TracerProvider(resource=_resource)
        _provider.add_span_processor(_BatchProcessor(_OTLPExporter(endpoint=_otel_endpoint, insecure=True)))
        _otel_trace.set_tracer_provider(_provider)
        _FAI().instrument_app(app)
        logger.info("otel_tracing_enabled", endpoint=_otel_endpoint)
    except ImportError:
        pass


class EmailRequest(BaseModel):
    raw_email: str


@app.get('/', include_in_schema=False)
async def dashboard():
    return FileResponse('app/templates/index.html')


def _role_for_api_key(ak: str):
    """Resolve the role for an API key SERVER-SIDE. Returns None if the key is unknown.
    The role is never taken from the client request (that let the shared key mint admin)."""
    if not ak:
        return None
    for pair in (getattr(settings, 'api_key_roles', '') or '').split(','):
        if ':' in pair:
            k, r = pair.split(':', 1)
            if ak == k.strip():
                return r.strip()
    if ak == getattr(settings, 'api_key', '') and getattr(settings, 'api_key', ''):
        return getattr(settings, 'api_key_role', 'analyst')
    return None


@app.post('/token')
async def get_token(body: dict):
    ak = body.get('api_key', '')
    role = _role_for_api_key(ak)          # server decides the role, not the client
    if role is None:
        raise HTTPException(status_code=401, detail='Unauthorized')
    sub = body.get('sub', 'api-client')
    return create_token_pair(sub=sub, role=role)


@app.post('/api/auth/refresh')
async def auth_refresh(body: dict):
    """Exchange a refresh token for a new access+refresh token pair."""
    from app.security.token_store import consume_refresh_token
    rt = body.get('refresh_token', '')
    if not rt:
        raise HTTPException(status_code=400, detail='refresh_token required')
    payload = consume_refresh_token(rt)
    if not payload:
        raise HTTPException(status_code=401, detail='Invalid or expired refresh token')
    return create_token_pair(sub=payload['sub'], role=payload['role'])


@app.get('/api/auth/whoami')
async def whoami(current_user: dict = Depends(require_auth)):
    """Return info about the current JWT holder."""
    return {
        'sub': current_user.get('sub'),
        'role': current_user.get('role', 'readonly'),
        'exp': current_user.get('exp'),
    }


@app.delete('/api/auth/revoke')
async def revoke_tokens(current_user: dict = Depends(require_auth)):
    """Revoke all refresh tokens for the current user."""
    from app.security.token_store import revoke_all_for_user
    count = revoke_all_for_user(current_user.get('sub', ''))
    return {'revoked': count}


@app.get('/api/audit/logs')
async def audit_logs(limit: int = 100, current_user: dict = Depends(require_permission('audit'))):
    """Return recent audit log entries (analyst+ only)."""
    return {'entries': read_audit_log(limit=limit)}


@app.get('/health')
async def health():
    import os as _os
    sa_path = getattr(settings, 'google_service_account_json', '')
    oauth_path = getattr(settings, 'gmail_oauth_token_file', '')
    sa_ok = bool(sa_path and _os.path.exists(sa_path) and getattr(settings, 'google_admin_impersonate_email', ''))
    oauth_ok = bool(oauth_path and _os.path.exists(oauth_path))
    smtp_ok = bool(getattr(settings, 'smtp_listen_port', 0))
    nlp_ok = bool(getattr(settings, 'anthropic_api_key', '') or getattr(settings, 'openai_api_key', '') or getattr(settings, 'gemini_api_key', ''))
    osint_ok = bool(settings.virustotal_api_key or settings.abuseipdb_api_key)
    soar_ok = bool(getattr(settings, 'elasticsearch_url', '') or getattr(settings, 'slack_webhook_url', '') or getattr(settings, 'jira_base_url', ''))
    ml_path = getattr(settings, 'ml_model_path', 'data/model.pkl')
    ml_ok = _os.path.exists(ml_path)
    from app.security.smtp_rate_limiter import stats as _smtp_rl_stats
    from app.security.bombing_detector import stats as _bomb_stats
    # Per-recipient buffered-mail breakdown (Tier 2/3 awaiting labeled release)
    _buf_state = {}
    try:
        import app.storage as _stg
        from app.layer7_gmail.smtp_receiver import RELEASE_WINDOW_SECS as _rwin
        _recips = {r: _stg.buffer_counts_by_tier(r) for r in _stg.buffer_active_recipients()}
        _buf_state = {'recipients': _recips, 'release_window_secs': _rwin}
    except Exception as _be:
        _buf_state = {'error': str(_be)}
    return {
        'status': 'ok',
        'smtp_rate_limiter': _smtp_rl_stats(),
        'bombing_detector': _bomb_stats(),
        'bombing_buffer': _buf_state,
        'virustotal_api': 'ok' if settings.virustotal_api_key else 'unconfigured',
        'abuseipdb_api': 'ok' if settings.abuseipdb_api_key else 'unconfigured',
        'urlhaus_api': 'ok',
        'phishtank_api': 'ok' if settings.phishtank_api_key else 'unconfigured',
        'misp_api': 'ok' if settings.misp_api_key else 'unconfigured',
        'anthropic_api': 'ok' if getattr(settings, 'anthropic_api_key', '') else 'unconfigured',
        'openai_api': 'ok' if settings.openai_api_key else 'unconfigured',
        'gemini_api': 'ok' if getattr(settings, 'gemini_api_key', '') else 'unconfigured',
        'layer1_osint_ok': osint_ok,
        'layer2_engines': {'nlp': 'ok' if nlp_ok else 'heuristic', 'behavioral': 'ok', 'structural': 'ok'},
        'layer2_ai_configured': nlp_ok,
        'layer3_sandbox_ok': True,
        'layer4_soar_configured': soar_ok,
        'layer5_ml_ok': ml_ok,
        'layer6_security_ok': True,
        'gmail_configured': sa_ok or oauth_ok or smtp_ok,
        'gmail_auth_mode': 'service_account' if sa_ok else ('oauth_user' if oauth_ok else ('smtp_only' if smtp_ok else 'none')),
    }


@app.post('/analyze')
async def analyze_email(
    request: Request,
    body: EmailRequest,
    _rl=Depends(_rate_limit),
    _auth=Depends(require_auth),
):
    start = time.time()
    email_id = str(uuid.uuid4())
    raw_bytes = body.raw_email.encode('utf-8')
    try:
        result = await run_pipeline(raw_bytes, settings)
    except Exception as exc:
        logger.error('pipeline_error', error=str(exc))
        raise HTTPException(status_code=500, detail=f'Pipeline error: {exc}')
    elapsed_ms = int((time.time() - start) * 1000)
    parsed = result.pop('parsed', None) or {}
    result['email_id'] = email_id
    result['processing_time_ms'] = elapsed_ms
    try:
        storage.save_scan(email_id, result, parsed)
    except Exception as exc:
        logger.warning('save_scan_error', error=str(exc))
    try:
        l3 = result.get('l3') if isinstance(result, dict) else None
        if l3 and isinstance(l3, dict):
            shot = l3.pop('screenshot_b64', None)
            if shot:
                import base64
                import os
                os.makedirs('data/screenshots', exist_ok=True)
                with open(f'data/screenshots/{email_id}.png', 'wb') as f:
                    f.write(base64.b64decode(shot))
    except Exception as exc:
        logger.warning('screenshot_save_error', error=str(exc))
    return result


@app.get('/report/{email_id}')
async def get_report(email_id: str):
    raise HTTPException(status_code=501, detail='Not yet implemented')


@app.get('/quarantine')
async def get_quarantine(page: int = 1, limit: int = 50):
    raise HTTPException(status_code=501, detail='Not yet implemented')


@app.get('/api/quarantine')
async def list_quarantine(limit: int = 50, offset: int = 0, _auth: dict = Depends(require_auth)):
    return {'items': storage.list_scans(limit=limit, offset=offset, only_quarantined=True)}


@app.get('/api/scans')
async def list_scans(limit: int = 50, offset: int = 0, verdict: str = None, hours: int = None, _auth: dict = Depends(require_auth)):
    since = (time.time() - hours * 3600) if hours else None
    return {'items': storage.list_scans(limit=limit, offset=offset, verdict_filter=verdict, since_ts=since)}


@app.get('/api/scan/{scan_id}')
async def get_scan_detail(scan_id: str, _auth: dict = Depends(require_auth)):
    s = storage.get_scan(scan_id)
    if not s:
        raise HTTPException(status_code=404, detail='Scan not found')
    # Never surface raw email body content via API
    if isinstance(s.get('data'), dict):
        parsed = s['data'].get('parsed') or {}
        parsed.pop('body_text', None)
        parsed.pop('body_html', None)
        parsed.pop('body_plain', None)
    s.pop('body_preview', None)
    return s


@app.post('/api/scan/{scan_id}/release')
async def release_scan(scan_id: str, _auth: dict = Depends(require_permission('release'))):
    storage.release_scan(scan_id)
    return {'ok': True}


@app.delete('/api/scan/{scan_id}')
async def delete_scan(scan_id: str, _auth: dict = Depends(require_permission('quarantine'))):
    storage.delete_scan(scan_id)
    return {'ok': True}


@app.get('/api/stats')
async def get_stats(hours: int = None, _auth: dict = Depends(require_auth)):
    since = (time.time() - hours * 3600) if hours else None
    return storage.get_stats(since_ts=since)


# ============== SOAR / Denylist endpoints ==============
from app.layer4_soar import denylist as _deny


@app.get('/api/denylist')
async def list_denylist(kind: str = None, only_active: bool = True, limit: int = 200, _auth: dict = Depends(require_auth)):
    return {
        'items': _deny.list_entries(kind=kind, only_active=only_active, limit=limit),
        'stats': _deny.stats(),
    }


@app.post('/api/denylist')
async def add_denylist(body: dict, _auth: dict = Depends(require_permission('denylist_write'))):
    kind = (body.get('kind') or '').strip().lower()
    value = (body.get('value') or '').strip().lower()
    reason = body.get('reason') or 'manual'
    if kind not in ('sender', 'domain', 'ip', 'url'):
        raise HTTPException(status_code=400, detail='kind must be sender|domain|ip|url')
    if not value:
        raise HTTPException(status_code=400, detail='value required')
    ok = _deny.add_entry(kind, value, reason=reason, added_by='manual')
    return {'ok': ok}


@app.delete('/api/denylist/{kind}/{value:path}')
async def remove_denylist(kind: str, value: str, _auth: dict = Depends(require_permission('denylist_write'))):
    ok = _deny.remove_entry(kind, value)
    return {'ok': ok}


@app.get('/api/bombing/status')
async def bombing_status(current_user: dict = Depends(require_auth)):
    """Return active inbox bombing attacks and detector thresholds."""
    from app.security.bombing_detector import stats as _bomb_stats
    return _bomb_stats()


@app.get('/api/bombing/active')
async def bombing_active(current_user: dict = Depends(require_auth)):
    """Active bombing events with per-recipient buffered-mail tier breakdown.

    Powers a dashboard banner: which inboxes are mid-bomb, how much noise/uncertain
    mail is buffered for each, and when it releases.
    """
    from app.security.bombing_detector import active_attacks as _active
    import app.storage as _stg
    from app.layer7_gmail.smtp_receiver import RELEASE_WINDOW_SECS as _rwin

    events = _active()                    # recipients currently in bombing mode
    by_rcpt = {e['rcpt']: e for e in events}
    # Fold in buffered counts for every recipient with held mail (mode may have
    # just exited while mail still awaits release).
    for rcpt in _stg.buffer_active_recipients():
        ev = by_rcpt.setdefault(rcpt, {'rcpt': rcpt})
        ev['buffered'] = _stg.buffer_counts_by_tier(rcpt)
    return {
        'active': list(by_rcpt.values()),
        'count': len(by_rcpt),
        'release_window_secs': _rwin,
    }


@app.post('/api/bombing/{rcpt}/clear')
async def clear_bombing(rcpt: str, current_user: dict = Depends(require_permission('quarantine'))):
    """SOC manually clears the bombing hold for a recipient inbox."""
    from app.security.bombing_detector import clear_attack
    clear_attack(rcpt)
    return {'ok': True, 'rcpt': rcpt, 'message': 'Bombing hold cleared'}


@app.get('/api/campaigns')
async def list_campaigns(days: int = 7, current_user: dict = Depends(require_auth)):
    """Detect and return active attack campaigns from recent scans."""
    from app.layer4_soar.campaign_detector import detect_campaigns
    db_path = getattr(settings, 'phishguard_db_path', 'data/phishguard.db') or 'data/phishguard.db'
    campaigns = detect_campaigns(db_path=db_path, window_days=days)
    active = sum(1 for c in campaigns if c.get('active'))
    return {'campaigns': campaigns, 'total': len(campaigns), 'active': active, 'window_days': days}


@app.post('/api/digest/send')
async def send_digest_now(current_user: dict = Depends(require_permission('soar'))):
    """Manually trigger the weekly threat digest to Slack."""
    from app.layer4_soar.digest import send_digest
    db_path   = getattr(settings, 'phishguard_db_path', 'data/phishguard.db') or 'data/phishguard.db'
    slack_url = getattr(settings, 'slack_webhook_url', '') or ''
    dash_url  = getattr(settings, 'dashboard_url', 'http://localhost:8000') or 'http://localhost:8000'
    result    = await send_digest(db_path=db_path, slack_webhook_url=slack_url, dashboard_url=dash_url)
    if not result.get('ok'):
        raise HTTPException(status_code=500, detail=result.get('error', 'failed'))
    return result


@app.get('/api/soar/status')
async def soar_status(_auth: dict = Depends(require_auth)):
    """Show which SOAR integrations are configured and reachable."""
    out = []
    es_url = getattr(settings, 'elasticsearch_url', '')
    es_ok = False
    if es_url:
        try:
            import httpx
            user = getattr(settings, 'elasticsearch_username', '')
            pwd = getattr(settings, 'elasticsearch_password', '')
            auth = (user, pwd) if user else None
            async with httpx.AsyncClient(verify=False) as c:
                r = await c.get(es_url, auth=auth, timeout=3)
                es_ok = r.status_code == 200
        except Exception:
            es_ok = False
    out.append({'name': 'Elasticsearch', 'configured': bool(es_url), 'reachable': es_ok, 'url': es_url})
    sl = getattr(settings, 'slack_webhook_url', '')
    out.append({'name': 'Slack', 'configured': bool(sl), 'reachable': bool(sl)})
    misp = getattr(settings, 'misp_url', '') and getattr(settings, 'misp_api_key', '')
    out.append({'name': 'MISP', 'configured': bool(misp), 'reachable': bool(misp)})
    octi = getattr(settings, 'opencti_url', '') and getattr(settings, 'opencti_token', '')
    out.append({'name': 'OpenCTI', 'configured': bool(octi), 'reachable': bool(octi)})
    jira_ok = bool(getattr(settings, 'jira_base_url', '') and getattr(settings, 'jira_api_token', ''))
    out.append({'name': 'Jira', 'configured': jira_ok, 'reachable': jira_ok})
    mail_ok = bool(getattr(settings, 'alert_smtp_host', '') and getattr(settings, 'alert_email_to', ''))
    out.append({'name': 'Email Alert', 'configured': mail_ok, 'reachable': mail_ok})
    out.append({'name': 'Denylist', 'configured': True, 'reachable': True})
    return {'integrations': out}


@app.get('/api/soar/audit')
async def soar_audit(limit: int = 50, _auth: dict = Depends(require_permission('audit'))):
    """Recent SOAR actions sourced from ES."""
    es_url = getattr(settings, 'elasticsearch_url', '')
    if not es_url:
        return {'items': [], 'source': 'es_unconfigured'}
    try:
        import httpx
        user = getattr(settings, 'elasticsearch_username', '')
        pwd = getattr(settings, 'elasticsearch_password', '')
        auth = (user, pwd) if user else None
        url = es_url.rstrip('/') + '/phishguard-verdicts-*/_search'
        q = {'size': limit, 'sort': [{'@timestamp': 'desc'}]}
        async with httpx.AsyncClient(verify=False) as c:
            r = await c.post(url, json=q, auth=auth, timeout=5)
            r.raise_for_status()
            data = r.json()
            hits = [h['_source'] for h in data.get('hits', {}).get('hits', [])]
            return {'items': hits, 'source': 'elasticsearch'}
    except Exception as exc:
        return {'items': [], 'error': str(exc)}



@app.get('/api/soar/test')
async def soar_test(_auth: dict = Depends(require_permission('soar'))):
    return await _run_soar_dryrun()


def _mask(val: str) -> str:
    if not val:
        return ''
    if len(val) <= 8:
        return '*' * len(val)
    return val[:4] + '*' * (len(val) - 8) + val[-4:]


_SETTINGS_OVERRIDE_PATH = os.environ.get("SETTINGS_OVERRIDE_FILE", "data/settings_overrides.json")
_PATCHABLE_KEYS: set[str] = {
    # OSINT keys
    "virustotal_api_key", "abuseipdb_api_key", "phishtank_api_key",
    "google_safe_browsing_api_key", "shodan_api_key",
    # Threat intel
    "misp_api_key", "misp_url", "misp_verify_ssl",
    "opencti_url", "opencti_token",
    # LLM providers
    "anthropic_api_key", "openai_api_key", "gemini_api_key",
    "llm_provider", "llm_model",
    # SOAR
    "slack_webhook_url", "jira_base_url", "jira_api_token",
    "jira_project_key", "jira_issue_type",
    # Alert email
    "alert_smtp_host", "alert_smtp_port", "alert_email_to",
    "alert_email_from",
    # ML / behaviour
    "enable_sandbox", "ml_bootstrap_on_startup",
    "l2_global_iso_min_samples", "l2_global_iso_retrain_interval",
    "l2_cold_high_value_roles",
}


def _load_overrides() -> dict:
    try:
        if os.path.exists(_SETTINGS_OVERRIDE_PATH):
            with open(_SETTINGS_OVERRIDE_PATH) as fh:
                return json.load(fh)
    except Exception:
        pass
    return {}


def _save_overrides(overrides: dict) -> None:
    os.makedirs(os.path.dirname(_SETTINGS_OVERRIDE_PATH) or ".", exist_ok=True)
    with open(_SETTINGS_OVERRIDE_PATH, "w") as fh:
        json.dump(overrides, fh, indent=2)


@app.patch('/api/settings')
async def patch_settings(body: dict, current_user: dict = Depends(require_permission('settings'))):
    """Update runtime configuration overrides (admin only). Sensitive values are masked in GET."""
    updates = {}
    rejected = []
    for key, val in body.items():
        if key not in _PATCHABLE_KEYS:
            rejected.append(key)
            continue
        updates[key] = str(val) if not isinstance(val, bool) else val
    if rejected:
        raise HTTPException(status_code=400, detail=f"Keys not patchable: {rejected}")
    overrides = _load_overrides()
    overrides.update(updates)
    _save_overrides(overrides)
    # Apply to the live settings object so restarts aren't required
    for k, v in updates.items():
        try:
            setattr(settings, k, v)
        except Exception:
            pass
    return {'updated': list(updates.keys()), 'total_overrides': len(overrides)}


@app.get('/api/settings')
async def get_settings(_auth: dict = Depends(require_permission('settings'))):
    overrides = _load_overrides()
    items = []
    keys = [
        # OSINT
        ('virustotal_api_key',          'VirusTotal'),
        ('abuseipdb_api_key',           'AbuseIPDB'),
        ('phishtank_api_key',           'PhishTank'),
        ('google_safe_browsing_api_key','Google Safe Browsing'),
        # NLP
        ('anthropic_api_key',           'Anthropic Claude (NLP)'),
        ('openai_api_key',              'OpenAI GPT (fallback)'),
        ('gemini_api_key',              'Google Gemini (fallback)'),
        # Threat intel
        ('misp_url',                    'MISP URL'),
        ('misp_api_key',                'MISP API Key'),
        ('opencti_url',                 'OpenCTI URL'),
        ('opencti_token',               'OpenCTI Token'),
        # SOAR
        ('slack_webhook_url',           'Slack alerts'),
        ('jira_base_url',               'Jira'),
        ('jira_api_token',              'Jira API Token'),
        # Alert email
        ('alert_smtp_host',             'Alert email SMTP'),
        ('alert_email_to',              'Alert email recipient'),
    ]
    for attr, label in keys:
        v = overrides.get(attr) or getattr(settings, attr, '') or ''
        items.append({
            'key': attr,
            'label': label,
            'configured': bool(v),
            'masked': _mask(v),
            'overridden': attr in overrides,
        })
    return {
        'providers': items,
        'thresholds': {
            'l1_domain_age_days': getattr(settings, 'l1_domain_age_days', 30),
            'l1_virustotal_threshold': getattr(settings, 'l1_virustotal_threshold', 3),
            'l1_abuseipdb_threshold': getattr(settings, 'l1_abuseipdb_threshold', 25),
            'l2_critical_threshold': getattr(settings, 'l2_critical_threshold', 0.9),
            'l2_composite_threshold': getattr(settings, 'l2_composite_threshold', 0.65),
        },
    }





@app.get('/api/evidence/{scan_id}/download')
async def download_evidence(
    scan_id: str,
    current_user: dict = Depends(require_permission('audit')),
):
    """Download the raw .eml file for a quarantined email (analyst+ only)."""
    from app.layer4_soar.evidence_store import get_evidence_local
    from fastapi.responses import Response

    # Try MinIO first
    try:
        from minio import Minio  # type: ignore
        endpoint   = settings.minio_endpoint
        access_key = settings.minio_access_key
        secret_key = settings.minio_secret_key
        bucket     = settings.minio_bucket
        secure     = settings.minio_secure
        client = Minio(endpoint, access_key=access_key, secret_key=secret_key, secure=secure)
        # Search for the key pattern
        objects = list(client.list_objects(bucket, prefix="", recursive=True))
        key = next((o.object_name for o in objects if scan_id in o.object_name and o.object_name.endswith(".eml")), None)
        if key:
            resp = client.get_object(bucket, key)
            data = resp.read()
            return Response(
                content=data,
                media_type="message/rfc822",
                headers={"Content-Disposition": f'attachment; filename="{scan_id}.eml"'},
            )
    except Exception:
        pass

    # Fallback to local filesystem
    data, _ = get_evidence_local(scan_id)
    if data:
        return Response(
            content=data,
            media_type="message/rfc822",
            headers={"Content-Disposition": f'attachment; filename="{scan_id}.eml"'},
        )
    raise HTTPException(status_code=404, detail="Evidence not found — email may have been scanned before evidence storage was enabled")


@app.get('/api/scan/{scan_id}/screenshot')
async def get_screenshot(scan_id: str, _auth: dict = Depends(require_auth)):
    import os
    path = f'data/screenshots/{scan_id}.png'
    if os.path.exists(path):
        return FileResponse(path, media_type='image/png')
    # Fallback: the L3 sandbox stores the screenshot as base64 in the scan data
    # (no PNG file is written to disk), so serve it from there when present.
    s = storage.get_scan(scan_id)
    b64 = (((s or {}).get('data') or {}).get('l3') or {}).get('screenshot_b64') if s else None
    if b64:
        import base64 as _b64
        from fastapi import Response as _Response
        return _Response(content=_b64.b64decode(b64), media_type='image/png')
    raise HTTPException(status_code=404, detail='No screenshot available')


# ---------------------------------------------------------------------------
# ThreatLens endpoints
# ---------------------------------------------------------------------------

@app.get('/api/intel/profiles')
async def list_intel_profiles(current_user: dict = Depends(require_permission('scan'))):
    """List all adversary profiles, sorted by generated_at desc."""
    from app.threatlens import store as tl_store
    profiles = tl_store.get_profiles()
    return [
        {
            "id":               p.id,
            "cluster_id":       p.cluster_id,
            "generated_at":     p.generated_at,
            "assessed_identity": p.assessed_identity,
            "suspected_apt":    p.suspected_apt,
            "assessed_intent":  p.assessed_intent,
            "severity":         p.severity,
            "confidence":       p.confidence,
            "ttp_count":        len(p.ttps),
            "surface_zones":    p.surface_zones,
            "segments":         p.segments,
            "summary":          p.summary,
        }
        for p in profiles
    ]


@app.get('/api/intel/profiles/{profile_id}')
async def get_intel_profile(
    profile_id: str,
    current_user: dict = Depends(require_permission('scan')),
):
    """Full profile with evidence chain. No raw email bodies."""
    from app.threatlens import store as tl_store
    profile = tl_store.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail='Profile not found')
    cluster = tl_store.get_cluster(profile.cluster_id)
    # Per-agent enrichment findings (provenance) — what each of the 11 agents
    # actually returned for this cluster. The dashboard's "Intelligence Sources"
    # cards group these by agent. (profile.evidence is the LLM's synthesized
    # evidence and is all tagged agent="profiler", so it can't populate the cards.)
    agent_findings = []
    for s in tl_store.get_intel_sources(profile.cluster_id):
        try:
            fj = json.loads(s.get("finding_json") or "{}")
        except Exception:
            fj = {}
        agent_findings.append({
            "agent":        s.get("agent"),
            "claim":        fj.get("claim", "") or s.get("source_title", ""),
            "source_url":   s.get("source_url"),
            "source_title": s.get("source_title"),
            "confidence":   s.get("confidence"),
        })
    return {
        "id":                profile.id,
        "cluster_id":        profile.cluster_id,
        "generated_at":      profile.generated_at,
        "assessed_identity": profile.assessed_identity,
        "suspected_apt":     profile.suspected_apt,
        "assessed_intent":   profile.assessed_intent,
        "severity":          profile.severity,
        "confidence":        profile.confidence,
        "ttps":              [t.model_dump() for t in profile.ttps],
        "surface_zones":     profile.surface_zones,
        "segments":          profile.segments,
        "claims":            [c.model_dump() for c in profile.claims],
        "evidence":          [
            {k: v for k, v in e.model_dump().items() if k not in ("raw",)}
            for e in profile.evidence
        ],
        "summary":           profile.summary,
        "model":             profile.model,
        "agent_findings":    agent_findings,
        "member_scan_count": len(cluster.member_scan_ids) if cluster else 0,
        "member_scan_ids":   cluster.member_scan_ids[:50] if cluster else [],
    }


@app.post('/api/intel/run')
async def run_intel_cycle(current_user: dict = Depends(require_admin())):
    """Trigger a ThreatLens profiling cycle (admin only)."""
    from app.threatlens.config import threatlens_settings
    if not threatlens_settings.intel_enabled:
        raise HTTPException(
            status_code=503,
            detail='ThreatLens is disabled. Set INTEL_ENABLED=true to activate.',
        )
    # Rebuild clusters from current scans first, so a manual run picks up new attacks
    # (run_cycle only profiles existing clusters). Best-effort, off the event loop.
    try:
        import asyncio as _asyncio
        from app.threatlens import actor_clusterer
        await _asyncio.get_event_loop().run_in_executor(None, actor_clusterer.refresh)
    except Exception as _exc:
        logger.warning("intel_cluster_refresh_err", error=str(_exc))
    from app.threatlens.orchestrator import run_cycle
    result = await run_cycle()
    return result


@app.get('/api/intel/graph')
async def intel_graph(
    current_user: dict = Depends(require_permission('scan')),
):
    """Threat actor relationship graph — intent-grouped nodes with infrastructure edges."""
    from app.threatlens import store as tl_store

    clusters = tl_store.get_active_clusters()
    profiles_list = tl_store.get_profiles()
    profiles = {p.cluster_id: p for p in profiles_list}

    # Only meaningful threat clusters — filter out noise
    NOISE = {"unknown", "legitimate", "clean", "unclear", "generic_phish", "", None}
    threat_clusters = [
        c for c in clusters
        if c.dominant_intent not in NOISE and len(c.member_scan_ids) >= 2
    ]

    # Sort by member count, take top 30
    threat_clusters.sort(key=lambda c: len(c.member_scan_ids), reverse=True)
    top = threat_clusters[:30]

    # Intent group metadata for coloring and grouping
    INTENT_META = {
        "credential_harvest":     {"color": "#3b82f6", "group": "Credential Theft"},
        "credential_harvesting":  {"color": "#3b82f6", "group": "Credential Theft"},
        "bec_fraud":              {"color": "#ef4444", "group": "BEC Fraud"},
        "fraud_payment":          {"color": "#f97316", "group": "Financial Fraud"},
        "fraud_scam":             {"color": "#f97316", "group": "Financial Fraud"},
        "brand_impersonation":    {"color": "#8b5cf6", "group": "Impersonation"},
        "executive_impersonation":{"color": "#a855f7", "group": "Impersonation"},
        "malware_delivery":       {"color": "#10b981", "group": "Malware"},
    }

    nodes = []
    for c in top:
        p = profiles.get(c.id)
        intent = c.dominant_intent or "other"
        meta = INTENT_META.get(intent, {"color": "#64748b", "group": "Other"})
        nodes.append({
            "id":           c.id[:12],
            "full_id":      c.id,
            "intent":       intent,
            "group":        meta["group"],
            "group_color":  meta["color"],
            "label":        intent.replace("_", " ").title(),
            "short_label":  intent.replace("credential_harvest", "Cred Theft")
                                  .replace("credential_harvesting", "Cred Theft")
                                  .replace("bec_fraud", "BEC Fraud")
                                  .replace("fraud_payment", "Fin. Fraud")
                                  .replace("brand_impersonation", "Brand Imp.")
                                  .replace("executive_impersonation", "Exec. Imp.")
                                  .replace("_", " ").title(),
            "member_count": len(c.member_scan_ids),
            "severity":     p.severity if p else "low",
            "confidence":   p.confidence if p else "speculative",
            "surface_zones": p.surface_zones if p else [],
            "ttp_ids":      [t.attack_id for t in p.ttps][:4] if p else [],
            "summary":      (p.summary or "")[:150] if p else "",
            "domains":      c.iocs.domains[:2],
        })

    # Build edges — only strong infrastructure/tradecraft overlaps
    edges = []
    for i, c1 in enumerate(top):
        for c2 in top[i+1:]:
            p1, p2 = profiles.get(c1.id), profiles.get(c2.id)

            # Shared IPs — strongest (same physical infrastructure)
            shared_ips = set(c1.iocs.ips) & set(c2.iocs.ips) - {""}
            if shared_ips:
                edges.append({
                    "from": c1.id[:12], "to": c2.id[:12],
                    "type": "shared_ip",
                    "label": f"Shared IP: {list(shared_ips)[0]}",
                    "weight": 1.0,
                })
                continue

            # Shared sending domain — same actor different campaigns
            shared_domains = set(c1.iocs.domains) & set(c2.iocs.domains) - {""}
            if shared_domains:
                edges.append({
                    "from": c1.id[:12], "to": c2.id[:12],
                    "type": "shared_domain",
                    "label": f"Domain: {list(shared_domains)[0]}",
                    "weight": 0.9,
                })
                continue

            # Shared ATT&CK techniques ≥ 3 — very similar tradecraft
            if p1 and p2:
                t1 = {t.attack_id for t in p1.ttps}
                t2 = {t.attack_id for t in p2.ttps}
                shared = t1 & t2
                if len(shared) >= 3:
                    edges.append({
                        "from": c1.id[:12], "to": c2.id[:12],
                        "type": "shared_ttps",
                        "label": f"{len(shared)} shared TTPs",
                        "weight": 0.7,
                    })

    # Group summary for the UI
    from collections import defaultdict
    groups: dict = defaultdict(list)
    for n in nodes:
        groups[n["group"]].append(n)

    group_list = [
        {"name": g, "count": len(ns), "color": ns[0]["group_color"]}
        for g, ns in sorted(groups.items(), key=lambda x: -len(x[1]))
    ]

    connected_ids = {e["from"] for e in edges} | {e["to"] for e in edges}

    return {
        "nodes": nodes,
        "edges": edges,
        "groups": group_list,
        "stats": {
            "total_clusters": len(clusters),
            "threat_clusters": len(threat_clusters),
            "shown":  len(nodes),
            "edges":  len(edges),
            "connected": len(connected_ids),
            "isolated": len(nodes) - len(connected_ids),
        },
    }


@app.post('/api/intel/graph/sync')
async def sync_intel_graph(current_user: dict = Depends(require_admin())):
    """Push current ThreatLens graph data to Neo4j."""
    from app.threatlens.orchestrator import _push_to_neo4j
    result = await _push_to_neo4j()
    return result


@app.get('/api/intel/status')
async def intel_status(current_user: dict = Depends(require_permission('scan'))):
    from app.threatlens.config import threatlens_settings
    from app.threatlens import store as tl_store
    clusters = tl_store.get_active_clusters()
    profiles = tl_store.get_profiles()
    return {
        "enabled":         threatlens_settings.intel_enabled,
        "active_clusters": len(clusters),
        "profiles":        len(profiles),
        "cadence":         threatlens_settings.intel_run_cadence,
    }


@app.get('/api/intel/clusters')
async def list_intel_clusters(current_user: dict = Depends(require_permission('scan'))):
    """List all active adversary clusters."""
    from app.threatlens import store as tl_store
    clusters = tl_store.get_active_clusters()
    return [
        {
            "id":             c.id,
            "first_seen":     c.first_seen,
            "last_seen":      c.last_seen,
            "member_count":   len(c.member_scan_ids),
            "dominant_intent": c.dominant_intent,
            "status":         c.status,
            "domains":        c.iocs.domains[:5],
        }
        for c in clusters
    ]


@app.get('/api/intel/rollup/sectors')
async def intel_rollup_sectors(current_user: dict = Depends(require_permission('scan'))):
    from app.threatlens.sector_rollup import sector_rollup
    return sector_rollup().model_dump()


@app.get('/api/intel/rollup/org')
async def intel_rollup_org(current_user: dict = Depends(require_permission('scan'))):
    from app.threatlens.sector_rollup import org_rollup
    return org_rollup().model_dump()


@app.get('/api/intel/rollup/network')
async def intel_rollup_network(current_user: dict = Depends(require_permission('scan'))):
    from app.threatlens.sector_rollup import network_rollup
    return network_rollup().model_dump()


@app.get('/api/intel/assessment')
async def get_intel_assessment(current_user: dict = Depends(require_permission('scan'))):
    """Return the latest org-level strategic threat assessment."""
    from app.threatlens import store as tl_store
    assessment = tl_store.get_latest_org_assessment()
    if not assessment:
        raise HTTPException(status_code=404, detail="No assessment yet — run a cycle first.")
    return {
        "id":                   assessment.id,
        "generated_at":         assessment.generated_at,
        "adversary_landscape":  assessment.adversary_landscape,
        "surface_pressure":     assessment.surface_pressure,
        "sector_pressure":      assessment.sector_pressure,
        "strategic_intent":     assessment.strategic_intent,
        "top_campaigns":        assessment.top_campaigns[:5],
        "source_profile_ids":   assessment.source_profile_ids,
        "confidence":           assessment.confidence,
        "summary":              assessment.summary,
    }


@app.post('/api/intel/assessment/export')
async def export_intel_assessment(current_user: dict = Depends(require_permission('scan'))):
    """Return a PDF-ready HTML leadership brief for the latest assessment."""
    from fastapi.responses import HTMLResponse
    from app.threatlens import store as tl_store
    from app.threatlens.org_assessor import build_brief_html
    assessment = tl_store.get_latest_org_assessment()
    if not assessment:
        raise HTTPException(status_code=404, detail="No assessment yet.")
    html = build_brief_html(assessment)
    return HTMLResponse(content=html)


@app.post('/api/intel/profiles/{profile_id}/export')
async def export_intel_profile(
    profile_id: str,
    current_user: dict = Depends(require_admin()),
):
    """Export a profile to MISP as an intrusion-set object."""
    from app.threatlens import store as tl_store
    profile = tl_store.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found.")
    cluster = tl_store.get_cluster(profile.cluster_id)

    # Construct intrusion-set shaped verdict_doc for the existing L4 MISP exporter
    verdict_doc = {
        "verdict":    "phishing",
        "confidence": 0.9,
        "sender":     cluster.iocs.domains[0] if cluster and cluster.iocs.domains else "",
        "blocked_at": "threatlens",
        "l1": {
            "hits":      cluster.iocs.domains[:5] if cluster else [],
            "sender_ip": cluster.iocs.ips[0] if cluster and cluster.iocs.ips else "",
        },
        "l2": {
            "engines": {
                "nlp": {
                    "intent":  profile.assessed_intent,
                    "tactics": [t.attack_id for t in profile.ttps[:3]],
                }
            }
        },
        "intel_profile": {
            "assessed_identity": profile.assessed_identity,
            "suspected_apt":     profile.suspected_apt,
            "confidence":        profile.confidence,
            "surface_zones":     profile.surface_zones,
            "summary":           profile.summary,
        },
    }

    try:
        from app.layer4_soar.misp_exporter import export_to_misp
        result = await export_to_misp(verdict_doc, settings)
        return {"status": "exported", "misp": result}
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"MISP export failed: {exc}")


@app.post('/api/intel/profiles/{profile_id}/feedback')
async def submit_profile_feedback(
    profile_id: str,
    request: Request,
    current_user: dict = Depends(require_permission('scan')),
):
    """Save analyst rating for a profile (actionable / not actionable / incorrect)."""
    from app.threatlens import store as tl_store
    body = await request.json()
    rating = body.get("rating", "")
    notes  = body.get("notes", "")
    if not rating:
        raise HTTPException(status_code=422, detail="rating is required")
    tl_store.save_profile_feedback(
        profile_id=profile_id,
        rating=rating,
        notes=notes,
        submitted_by=current_user.get("sub", "soc"),
    )
    return {"status": "saved"}




async def _run_soar_dryrun():
    """Probe every SOAR integration without dispatching real alerts."""
    import asyncio as _aio

    import httpx as _hx

    from app.layer4_soar.email_alerter import probe_email as _pe
    from app.layer4_soar.jira_exporter import probe_jira as _pj

    async def _probe_es():
        url = getattr(settings, "elasticsearch_url", "")
        if not url:
            return {"configured": False, "reachable": False}
        try:
            user = getattr(settings, "elasticsearch_username", "")
            pwd = getattr(settings, "elasticsearch_password", "")
            auth = (user, pwd) if user else None
            async with _hx.AsyncClient(verify=False) as c:
                r = await c.get(url, auth=auth, timeout=3)
                return {"configured": True, "reachable": r.status_code == 200, "status": r.status_code}
        except Exception as exc:
            return {"configured": True, "reachable": False, "error": str(exc)}

    async def _probe_slack():
        u = getattr(settings, "slack_webhook_url", "")
        return {"configured": bool(u), "reachable": bool(u), "note": "webhook URL not pinged in dry-run"}

    async def _probe_misp():
        u = getattr(settings, "misp_url", "")
        k = getattr(settings, "misp_api_key", "")
        if not (u and k):
            return {"configured": False, "reachable": False}
        try:
            async with _hx.AsyncClient(verify=False) as c:
                r = await c.get(u.rstrip("/") + "/servers/getVersion",
                    headers={"Authorization": k, "Accept": "application/json"}, timeout=5)
                return {"configured": True, "reachable": r.status_code == 200, "status": r.status_code}
        except Exception as exc:
            return {"configured": True, "reachable": False, "error": str(exc)}

    async def _probe_opencti():
        u = getattr(settings, "opencti_url", "")
        t = getattr(settings, "opencti_token", "")
        return {"configured": bool(u and t), "reachable": bool(u and t), "note": "graphql ping not implemented in dry-run"}

    async def _probe_denylist():
        try:
            from app.layer4_soar import denylist as _dl
            s = _dl.stats()
            return {"configured": True, "reachable": True, "stats": s}
        except Exception as exc:
            return {"configured": True, "reachable": False, "error": str(exc)}

    es, sl, mi, oc, ji, ml, dl = await _aio.gather(
        _probe_es(), _probe_slack(), _probe_misp(), _probe_opencti(),
        _pj(settings), _pe(settings), _probe_denylist(),
    )
    return {
        "integrations": {
            "elasticsearch": es,
            "slack": sl,
            "misp": mi,
            "opencti": oc,
            "jira": ji,
            "email": ml,
            "denylist": dl,
        }
    }


# ============== Gmail Layer 7 endpoints ==============

@app.post("/api/gmail/watch")
async def gmail_watch(current_user: dict = Depends(require_permission("gmail_write"))):
    from app.layer7_gmail.gmail_setup import setup_gmail_watch as _sgw
    return _sgw(settings)

@app.delete("/api/gmail/watch")
async def gmail_watch_stop(current_user: dict = Depends(require_permission("gmail_write"))):
    from app.layer7_gmail.gmail_setup import stop_gmail_watch as _stw
    return {"ok": _stw(settings)}

@app.post("/api/gmail/renew")
async def gmail_watch_renew(current_user: dict = Depends(require_permission("gmail_write"))):
    from app.layer7_gmail.gmail_setup import renew_gmail_watch as _rnw
    return _rnw(settings)

@app.post("/api/gmail/push")
async def gmail_push(request: Request):
    from app.layer7_gmail.pubsub_watcher import handle_push_notification as _hpn
    from app.pipeline import analyze_email as _aeb
    body = await request.json()
    return await _hpn(body, _aeb, settings)

_scan_progress: dict = {}   # scan_id → progress dict (in-memory, single process)


@app.post("/api/gmail/scan")
async def gmail_scan(
    query: str = "",
    max_messages: int = 100,
    current_user: dict = Depends(require_permission("scan")),
):
    import uuid as _uuid
    from app.layer7_gmail.historical_scanner import scan_inbox as _si
    from app.pipeline import analyze_email as _aeb

    scan_id = str(_uuid.uuid4())
    _scan_progress[scan_id] = {
        "status": "running", "scan_id": scan_id,
        "total": 0, "scanned": 0, "skipped": 0,
        "phishing": 0, "suspicious": 0, "clean": 0, "errors": 0,
    }
    try:
        result = await _si(_aeb, settings, query=query, max_messages=max_messages)
        _scan_progress[scan_id] = {**_scan_progress[scan_id], **result, "status": "complete"}
        return {**result, "scan_id": scan_id, "status": "complete"}
    except Exception as exc:
        _scan_progress[scan_id]["status"] = "error"
        _scan_progress[scan_id]["error"] = str(exc)
        raise


@app.get("/api/gmail/scan/status")
async def gmail_scan_status(
    scan_id: str = "",
    current_user: dict = Depends(require_permission("scan")),
):
    """Get progress of a Gmail scan. Omit scan_id to get all recent scans."""
    if scan_id:
        prog = _scan_progress.get(scan_id)
        if not prog:
            raise HTTPException(status_code=404, detail="Scan not found")
        return prog
    return {"scans": list(_scan_progress.values())[-10:]}

@app.get("/api/pending")
async def list_pending(current_user: dict = Depends(require_permission("scan"))):
    """List emails held for SOC review (suspicious emails awaiting approval)."""
    return {"items": storage.list_pending_reviews("pending"),
            "total": len(storage.list_pending_reviews("pending"))}


@app.post("/api/pending/{pending_id}/approve")
async def approve_pending(
    pending_id: str,
    current_user: dict = Depends(require_permission("quarantine")),
):
    """SOC approves a suspicious email — delivers it to the original recipient."""
    from app.layer7_gmail.smtp_receiver import deliver_pending
    result = await deliver_pending(pending_id, settings,
                                   reviewed_by=current_user.get("sub", "soc"))
    if not result.get("ok"):
        raise HTTPException(status_code=404, detail=result.get("error", "failed"))
    return result


@app.post("/api/pending/{pending_id}/reject")
async def reject_pending(
    pending_id: str,
    current_user: dict = Depends(require_permission("quarantine")),
):
    """SOC rejects a suspicious email — sends it to quarantine."""
    from app.layer7_gmail.smtp_receiver import reject_pending
    result = await reject_pending(pending_id, settings,
                                  reviewed_by=current_user.get("sub", "soc"))
    if not result.get("ok"):
        raise HTTPException(status_code=404, detail=result.get("error", "failed"))
    return result



@app.get("/api/trusted-domains")
async def list_trusted_domains_api(current_user: dict = Depends(require_auth)):
    from app.layer1.verdicts import TRUSTED_SENDER_DOMAINS
    builtin = [{"domain": d, "source": "builtin"} for d in sorted(TRUSTED_SENDER_DOMAINS)]
    dynamic = [{"domain": r["domain"], "source": "user", "note": r.get("note", ""),
                "added_at": r.get("added_at")} for r in storage.list_trusted_domains()]
    return {"builtin": builtin, "user_added": dynamic,
            "total": len(builtin) + len(dynamic)}


@app.post("/api/trusted-domains")
async def add_trusted_domain_api(body: dict, current_user: dict = Depends(require_permission("settings"))):
    domain = (body.get("domain") or "").strip().lower()
    if not domain or "." not in domain:
        raise HTTPException(status_code=400, detail="Invalid domain")
    note = body.get("note", "")
    ok = storage.add_trusted_domain(domain, note=note, added_by=current_user.get("sub", "soc"))
    if not ok:
        raise HTTPException(status_code=500, detail="Failed to add domain")
    return {"ok": True, "domain": domain}


@app.delete("/api/trusted-domains/{domain}")
async def remove_trusted_domain_api(domain: str, current_user: dict = Depends(require_permission("settings"))):
    storage.remove_trusted_domain(domain)
    return {"ok": True, "domain": domain}


@app.post("/api/scan/{scan_id}/feedback")
async def submit_feedback(scan_id: str, body: dict,
                          current_user: dict = Depends(require_permission("scan"))):
    corrected = body.get("corrected_verdict", "")
    if corrected not in ("phishing", "suspicious", "clean"):
        raise HTTPException(status_code=400, detail="corrected_verdict must be phishing/suspicious/clean")
    scan = storage.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    original = scan.get("verdict", "unknown")
    storage.save_feedback(scan_id, original, corrected,
                          notes=body.get("notes", ""),
                          submitted_by=current_user.get("sub", "soc"))
    return {"ok": True, "scan_id": scan_id, "original": original, "corrected": corrected}


@app.get("/api/gmail/status")
async def gmail_status(current_user: dict = Depends(require_auth)):
    import os as _os
    sa_path = getattr(settings, "google_service_account_json", "")
    impersonate = getattr(settings, "google_admin_impersonate_email", "")
    oauth_path = getattr(settings, "gmail_oauth_token_file", "")
    sa_ok = bool(sa_path and _os.path.exists(sa_path) and impersonate)
    oauth_ok = bool(oauth_path and _os.path.exists(oauth_path))
    if sa_ok:
        auth_mode = "service_account"
    elif oauth_ok:
        auth_mode = "oauth_user"
    else:
        auth_mode = "none"
    push_ready = sa_ok and bool(getattr(settings, "google_cloud_project", ""))
    return {
        "auth_mode": auth_mode,
        "service_account_file": sa_path,
        "service_account_ok": sa_ok,
        "admin_email": impersonate,
        "oauth_token_file": oauth_path,
        "oauth_token_ok": oauth_ok,
        "cloud_project": getattr(settings, "google_cloud_project", ""),
        "queue_topic": getattr(settings, "gmail_queue_topic", ""),
        "queue_subscription": getattr(settings, "gmail_queue_subscription", ""),
        "push_endpoint": getattr(settings, "gmail_push_endpoint", ""),
        "push_notifications_ready": push_ready,
        "pull_enabled": getattr(settings, "gmail_enable_pull_subscriber", False),
        "quarantine_label": settings.gmail_quarantine_label,
        "scanned_label": settings.gmail_scanned_label,
    }


# ============== Layer 5 ML endpoints ==============

@app.get("/api/ml/status")
async def ml_status(current_user: dict = Depends(require_auth)):
    from app.layer5_ml.classifier import model_info as _mi
    return _mi(getattr(settings, "ml_model_path", "data/model.pkl"))

@app.post("/api/ml/retrain")
async def ml_retrain(current_user: dict = Depends(require_permission("ml_retrain"))):
    from app.layer5_ml.retrain import retrain as _rt
    data_dir = getattr(settings, "ml_local_data_dir", "data/training")
    model_out = getattr(settings, "ml_model_path", "data/model.pkl")
    return _rt(data_dir=data_dir, model_out=model_out)

@app.post("/api/ml/bootstrap")
async def ml_bootstrap(current_user: dict = Depends(require_permission("ml_retrain"))):
    from app.layer5_ml.bootstrap import bootstrap_and_train as _bat
    data_dir = getattr(settings, "ml_local_data_dir", "data/training")
    model_out = getattr(settings, "ml_model_path", "data/model.pkl")
    return _bat(data_dir=data_dir, model_out=model_out)

@app.post("/api/ml/predict")
async def ml_predict(body: dict, current_user: dict = Depends(require_permission("scan"))):
    from app.layer5_ml.classifier import predict as _pred
    model_out = getattr(settings, "ml_model_path", "data/model.pkl")
    return _pred(body, model_path=model_out)
