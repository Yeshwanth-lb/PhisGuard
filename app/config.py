from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @model_validator(mode="after")
    def _threat_intel_creds_fallback(self):
        import os as _os
        # The working MISP automation key lives in MISP_KEY; MISP_API_KEY is a stale
        # placeholder ("z"). Fall back to MISP_KEY so the app authenticates to MISP.
        if not self.misp_api_key or len(self.misp_api_key) < 10:
            alt = _os.environ.get("MISP_KEY", "")
            if alt:
                self.misp_api_key = alt
        # OpenCTI admin token isn't in the app env; read it from the mounted (gitignored)
        # credentials dir so the SOAR OpenCTI export can authenticate.
        if not self.opencti_token:
            p = "credentials/opencti_token"
            if _os.path.exists(p):
                self.opencti_token = open(p).read().strip()
        return self

    # ── Auth ──────────────────────────────────────────────────────────────────
    phishguard_api_key: str = Field(default="dev-key")
    api_key: str = Field(default="dev-key")
    # Role granted to holders of the single shared api_key (server-decided, never
    # chosen by the client). Optional per-key map: "keyA:admin,keyB:analyst".
    api_key_role: str = Field(default="analyst")
    api_key_roles: str = Field(default="")
    jwt_secret: str = Field(default="change-me-in-production")
    # Allowed CORS origins for the dashboard (comma-separated). Wildcard '*' with
    # credentials is unsafe, so default to the local dashboard origins.
    cors_allow_origins: str = Field(default="http://localhost:8000,http://127.0.0.1:8000")

    # ── LLM provider (used by all AI layers) ─────────────────────────────────
    # auto = detect from whichever key is set (claude → openai → gemini → heuristic)
    # or set explicitly: claude | openai | gemini | heuristic
    llm_provider: str = Field(default="auto")
    llm_model: str = Field(default="")   # leave blank to use provider default

    # ── API keys — set whichever provider you use ─────────────────────────────
    anthropic_api_key: str = Field(default="")
    anthropic_model: str = Field(default="claude-opus-4-7")
    anthropic_max_tokens: int = Field(default=1024)
    gemini_api_key: str = Field(default="")
    openai_api_key: str = Field(default="")
    # Self-consistency voting for the NLP engine: sample the LLM N times and take
    # the MEDIAN score. Reduces run-to-run verdict flip-flop on borderline mail
    # without shifting the score distribution (so no threshold recalibration,
    # unlike temperature=0 which regressed detection). Default 1 = single call =
    # no extra cost/latency; set 3 for reproducibility-sensitive deployments.
    nlp_self_consistency_samples: int = Field(default=1)

    # ── Layer 1 OSINT APIs ────────────────────────────────────────────────────
    virustotal_api_key: str = Field(default="")
    abuseipdb_api_key: str = Field(default="")
    phishtank_api_key: str = Field(default="")
    google_safe_browsing_api_key: str = Field(default="")
    shodan_api_key: str = Field(default="")
    l1_domain_age_days: int = Field(default=30)
    l1_virustotal_threshold: int = Field(default=3)
    l1_abuseipdb_threshold: int = Field(default=25)
    l1_misp_threat_levels: str = Field(default="High,Medium")

    # ── MISP ──────────────────────────────────────────────────────────────────
    misp_url: str = Field(default="")
    misp_api_key: str = Field(default="")
    misp_verify_ssl: bool = Field(default=False)
    misp_default_tlp: str = Field(default="TLP:AMBER")
    misp_org_id: int = Field(default=1)

    # ── Elasticsearch ─────────────────────────────────────────────────────────
    elasticsearch_url: str = Field(default="http://127.0.0.1:9200")
    elasticsearch_username: str = Field(default="elastic")
    elasticsearch_password: str = Field(default="changeme")

    # ── OpenCTI ───────────────────────────────────────────────────────────────
    opencti_url: str = Field(default="")
    opencti_token: str = Field(default="")
    opencti_admin_email: str = Field(default="admin@phishguard.local")
    opencti_admin_password: str = Field(default="changeme")
    opencti_host: str = Field(default="http://opencti:8080")
    opencti_misp_sync_interval: int = Field(default=60)

    # ── Neo4j (ThreatLens graph) ─────────────────────────────────────────────
    neo4j_uri: str = Field(default="bolt://neo4j:7687")
    neo4j_user: str = Field(default="neo4j")
    neo4j_password: str = Field(default="changeme123")

    # ── Redis ─────────────────────────────────────────────────────────────────
    redis_host: str = Field(default="redis")
    redis_port: int = Field(default=6379)
    redis_url: str = Field(default="redis://127.0.0.1:6379/0")

    # ── Layer 3 Sandbox ───────────────────────────────────────────────────────
    enable_sandbox: bool = Field(default=False)
    l3_trigger_threshold: float = Field(default=0.45)
    sandbox_docker_image: str = Field(default="")
    max_sandbox_containers: int = Field(default=5)
    sandbox_timeout_seconds: int = Field(default=60)
    l3_max_detonations: int = Field(default=5)   # max URLs detonated per email (attacker hides payload behind a clean first link)
    # ── Layer 3 attachment static analysis (macro/executable/archive) ─────────
    enable_attachment_analysis: bool = Field(default=True)
    max_attachment_scan_bytes: int = Field(default=25 * 1024 * 1024)

    # ── Layer 4 SOAR ─────────────────────────────────────────────────────────
    slack_webhook_url: str = Field(default="")

    # Jira
    jira_base_url: str = Field(default="")
    jira_email: str = Field(default="")
    jira_api_token: str = Field(default="")
    jira_project_key: str = Field(default="")
    jira_issue_type: str = Field(default="Task")

    # Alert email
    alert_smtp_host: str = Field(default="")
    alert_smtp_port: int = Field(default=587)
    alert_smtp_user: str = Field(default="")
    alert_smtp_password: str = Field(default="")
    alert_smtp_use_tls: bool = Field(default=True)
    alert_email_from: str = Field(default="phishguard@example.com")
    alert_email_to: str = Field(default="")

    # ── Layer 7 Gmail / Google Workspace ─────────────────────────────────────
    google_service_account_json: str = Field(default="credentials/sa.json")
    google_workspace_domain: str = Field(default="")
    google_admin_impersonate_email: str = Field(default="")
    gmail_quarantine_label: str = Field(default="PhishGuard-Quarantine")
    gmail_scanned_label: str = Field(default="PhishGuard-Scanned")
    gmail_quarantine_address: str = Field(default="")
    gmail_oauth_token_file: str = Field(default="credentials/gmail_oauth_token.json")
    gmail_oauth_client_secret: str = Field(default="credentials/gmail_oauth_client.json")
    google_cloud_project: str = Field(default="")
    gmail_queue_topic: str = Field(default="phishguard-gmail-notifications")
    gmail_queue_subscription: str = Field(default="phishguard-gmail-sub")
    gmail_push_endpoint: str = Field(default="")
    gmail_enable_pull_subscriber: bool = Field(default=False)
    # When true, Gmail-ingested mail (push + historical) is fed through the SAME
    # bombing detection+triage pipeline as the SMTP gateway. Default off: fully
    # dormant — no Gmail API calls, no startup errors — production is a one-flag flip.
    inbox_ingestion_enabled: bool = Field(default=False)

    # ── SMTP inbound gateway ──────────────────────────────────────────────────
    smtp_listen_host: str = Field(default="0.0.0.0")
    smtp_listen_port: int = Field(default=8025)   # 8025 = no root needed; map to 25 in prod
    smtp_relay_host: str = Field(default="smtp-relay.gmail.com")
    smtp_relay_port: int = Field(default=587)
    smtp_allowed_ips: str = Field(default="")
    max_smtp_connections: int = Field(default=50)

    # ── Layer 5 ML ────────────────────────────────────────────────────────────
    ml_model_path: str = Field(default="data/model.pkl")
    ml_local_data_dir: str = Field(default="data/training")    # ground-truth corpus only
    ml_verdict_log_dir: str = Field(default="data/verdicts")   # live predictions (NOT training)
    ml_bootstrap_on_startup: bool = Field(default=True)
    # Automated feedback-loop retraining (opt-in — retrains on accumulated SOC
    # feedback on a cadence, but only PROMOTES the new model if it doesn't
    # regress the champion's held-out AUC — see auto_retrain.py).
    ml_auto_retrain_enabled: bool = Field(default=False)
    ml_retrain_cadence_days: int = Field(default=7)
    ml_promote_auc_tolerance: float = Field(default=0.01)   # accept new model if new_auc >= champion_auc - this

    # MLflow
    mlflow_tracking_uri: str = Field(default="http://127.0.0.1:5000")

    # MinIO evidence store (self-hosted S3 for SOC team)
    minio_endpoint: str = Field(default="minio:9000")
    minio_access_key: str = Field(default="phishguard")
    minio_secret_key: str = Field(default="changeme123")
    minio_bucket: str = Field(default="phishguard-evidence")
    minio_secure: bool = Field(default=False)

    # Cloud storage
    ml_s3_bucket: str = Field(default="")
    aws_s3_bucket: str = Field(default="phishguard-threat-samples")
    aws_region: str = Field(default="us-east-1")
    gcs_bucket: str = Field(default="phishguard-threat-samples")
    gcs_project: str = Field(default="")

    # ── Layer 2 weights & thresholds ─────────────────────────────────────────
    l2_nlp_weight: float = Field(default=0.40)
    l2_behavioral_weight: float = Field(default=0.35)
    l2_structural_weight: float = Field(default=0.25)
    l2_critical_threshold: float = Field(default=0.90)
    l2_composite_threshold: float = Field(default=0.65)
    l2_majority_vote_threshold: float = Field(default=0.50)
    l2_engine_timeout_seconds: int = Field(default=5)
    l2_baseline_min_emails: int = Field(default=20)
    l2_domain_age_threshold_days: int = Field(default=30)
    l2_typosquatting_distance: int = Field(default=2)
    # Authenticated-sender fast-pass: a DMARC-aligned message from an established,
    # non-abusive domain isn't condemned by content tactics (urgency/verify/link) —
    # reduces false positives on legit OTP/transactional mail. Reputation-gated.
    auth_sender_fastpass: bool = Field(default=True)

    # Engine 3 cold start
    l2_global_iso_model_path: str = Field(default="models/global_iso_v1.pkl")
    l2_global_iso_min_samples: int = Field(default=50)
    l2_global_iso_retrain_interval: int = Field(default=500)
    l2_cold_high_value_roles: str = Field(default="cfo,ceo,cto,ciso,finance,payroll,hr,legal")

    @property
    def misp_threat_level_list(self) -> list[str]:
        return [t.strip() for t in self.l1_misp_threat_levels.split(",")]

    @property
    def cold_high_value_role_list(self) -> list[str]:
        return [r.strip().lower() for r in self.l2_cold_high_value_roles.split(",")]


settings = Settings()


# Fields whose Field(default=...) is a well-known placeholder, not a real secret —
# shipping these unchanged into a real deployment means the credential is public
# knowledge (it's sitting in this file's git history). Unlike JWT_SECRET, these
# gate optional integrations (ES/OpenCTI/MinIO/Neo4j), so a hard startup failure
# would be too aggressive for a deployment that doesn't use one of them — warn
# loudly instead, once, at startup.
_INSECURE_DEFAULTS = {
    "elasticsearch_password": "changeme",
    "opencti_admin_password": "changeme",
    "minio_secret_key": "changeme123",
    "neo4j_password": "changeme123",
}


def warn_insecure_defaults() -> list[str]:
    """Log a warning for every credential still on its known-weak default.
    Call once at startup. Returns the list of field names still insecure,
    for callers that want to act on it (tests, health checks)."""
    import structlog
    logger = structlog.get_logger()
    still_default = [
        field for field, default_value in _INSECURE_DEFAULTS.items()
        if getattr(settings, field, None) == default_value
    ]
    if still_default:
        logger.warning(
            "insecure_default_credentials",
            fields=still_default,
            hint="Set these in .env before a real deployment — the shipped defaults are public.",
        )
    return still_default
