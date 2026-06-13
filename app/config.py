from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
from typing import List


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # API auth
    phishguard_api_key: str = Field(default="dev-key")
    api_key: str = Field(default="dev-key")
    jwt_secret: str = Field(default="change-me-in-production")

    # OpenAI
    openai_api_key: str = Field(default="")

    # OSINT APIs
    virustotal_api_key: str = Field(default="")
    abuseipdb_api_key: str = Field(default="")
    phishtank_api_key: str = Field(default="")
    shodan_api_key: str = Field(default="")

    # MISP
    misp_url: str = Field(default="")
    misp_api_key: str = Field(default="")
    misp_verify_ssl: bool = Field(default=False)
    misp_default_tlp: str = Field(default="TLP:AMBER")
    misp_org_id: int = Field(default=1)

    elasticsearch_url: str = Field(default="")
    # Elasticsearch
    elasticsearch_host: str = Field(default="http://127.0.0.1:9200")
    elasticsearch_username: str = Field(default="elastic")
    elasticsearch_password: str = Field(default="changeme")

    opencti_url: str = Field(default="")
    opencti_token: str = Field(default="")
    # OpenCTI
    opencti_admin_email: str = Field(default="admin@phishguard.local")
    opencti_admin_password: str = Field(default="changeme")
    opencti_host: str = Field(default="http://opencti:8080")
    opencti_misp_sync_interval: int = Field(default=60)

    # Redis
    redis_host: str = Field(default="redis")
    redis_port: int = Field(default=6379)

    # Slack
    slack_webhook_url: str = Field(default="")

    # Google Workspace
    google_service_account_json: str = Field(default="credentials/sa.json")
    google_workspace_domain: str = Field(default="")
    google_admin_impersonate_email: str = Field(default="")
    gmail_quarantine_label: str = Field(default="PhishGuard-Quarantine")
    gmail_scanned_label: str = Field(default="PhishGuard-Scanned")
    gmail_quarantine_address: str = Field(default="")

    # SMTP server
    smtp_listen_host: str = Field(default="0.0.0.0")
    smtp_listen_port: int = Field(default=25)
    smtp_relay_host: str = Field(default="smtp-relay.gmail.com")
    smtp_relay_port: int = Field(default=587)
    smtp_allowed_ips: str = Field(default="")
    max_smtp_connections: int = Field(default=50)

    # ML training storage
    ml_s3_bucket: str = Field(default="")
    ml_local_data_dir: str = Field(default="data/training")

    # Cloud storage
    aws_s3_bucket: str = Field(default="phishguard-threat-samples")
    aws_region: str = Field(default="us-east-1")
    gcs_bucket: str = Field(default="phishguard-threat-samples")
    gcs_project: str = Field(default="")

    # MLflow
    mlflow_tracking_uri: str = Field(default="http://127.0.0.1:5000")

    # Layer 1 thresholds
    l1_virustotal_threshold: int = Field(default=3)
    l1_abuseipdb_threshold: int = Field(default=25)
    l1_misp_threat_levels: str = Field(default="High,Medium")

    # Layer 2 weights
    l2_nlp_weight: float = Field(default=0.40)
    l2_behavioral_weight: float = Field(default=0.35)
    l2_structural_weight: float = Field(default=0.25)

    # Layer 2 verdict thresholds
    l2_critical_threshold: float = Field(default=0.90)
    l2_composite_threshold: float = Field(default=0.65)
    l2_majority_vote_threshold: float = Field(default=0.50)

    # Layer 2 engine behavior
    l2_engine_timeout_seconds: int = Field(default=5)
    l2_baseline_min_emails: int = Field(default=20)
    l2_domain_age_threshold_days: int = Field(default=30)
    l2_typosquatting_distance: int = Field(default=2)

    # Engine 3 cold start
    l2_global_iso_model_path: str = Field(default="models/global_iso_v1.pkl")
    l2_global_iso_min_samples: int = Field(default=50)
    l2_global_iso_retrain_interval: int = Field(default=500)
    l2_cold_high_value_roles: str = Field(default="cfo,ceo,cto,ciso,finance,payroll,hr,legal")

    # Sandbox
    max_sandbox_containers: int = Field(default=5)
    sandbox_timeout_seconds: int = Field(default=60)

    @property
    def misp_threat_level_list(self) -> List[str]:
        return [t.strip() for t in self.l1_misp_threat_levels.split(",")]

    @property
    def cold_high_value_role_list(self) -> List[str]:
        return [r.strip().lower() for r in self.l2_cold_high_value_roles.split(",")]


settings = Settings()
