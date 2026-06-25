from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ThreatLensSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Master switch — off by default, activate after Phase 1 verified green
    intel_enabled: bool = Field(default=False)

    # Clustering
    intel_cluster_sim_threshold: float = Field(default=0.72)
    intel_cluster_dormant_days: int = Field(default=14)

    # Scheduling
    intel_run_cadence: str = Field(default="daily")  # daily | hourly | on_campaign

    # Agent behaviour
    intel_agent_timeout_secs: int = Field(default=30)
    intel_max_cluster_concurrency: int = Field(default=4)
    intel_cache_ttl_secs: int = Field(default=86400)

    # Paths
    intel_allowlist_path: str = Field(default="app/threatlens/scraper/allowlist.yaml")
    intel_surface_taxonomy_path: str = Field(default="app/threatlens/data/attack_surface.yaml")

    # Agent registry toggle (comma-separated names)
    intel_enabled_agents: str = Field(
        default="osint,attack,misp,ioc,cve,compromise,telecom"
    )

    # Monitored identifiers
    intel_monitored_domains: str = Field(default="skylo.tech")
    intel_monitored_sectors: str = Field(
        default="maritime,logistics,mining,agriculture,automotive,telecom"
    )

    # Retention
    intel_retention_days: int = Field(default=90)

    # Scraper
    intel_scraper_default: str = Field(default="crawl4ai")
    intel_scrapling_ai_targeted: bool = Field(default=True)
    intel_crawl4ai_headless: bool = Field(default=True)
    intel_fetch_rate_per_domain: int = Field(default=6)
    intel_fetch_timeout_secs: int = Field(default=20)

    # Free community feed keys (blank = not_configured, agent self-reports)
    abusech_auth_key: str = Field(default="")
    otx_api_key: str = Field(default="")
    pulsedive_api_key: str = Field(default="")
    nvd_api_key: str = Field(default="")

    # Free-with-signup keys
    greynoise_api_key: str = Field(default="")
    urlscan_api_key: str = Field(default="")
    ipinfo_api_key: str = Field(default="")
    intelx_api_key: str = Field(default="")    # intelx.io — dark/deep web search
    leakix_api_key: str = Field(default="")    # leakix.net — exposed service search
    securitytrails_api_key: str = Field(default="")
    emailrep_api_key: str = Field(default="")
    virustotal_api_key: str = Field(default="")  # reuse from L1 if set

    # Truly free, no key required (Shodan InternetDB, BGPView, RIPE, crt.sh)
    # These agents are always configured — no key check needed

    # Optional commercial connectors — blank by default, activate by supplying key
    hibp_api_key: str = Field(default="")
    dehashed_api_key: str = Field(default="")
    spycloud_api_key: str = Field(default="")
    rf_api_key: str = Field(default="")
    intel471_api_key: str = Field(default="")
    flare_api_key: str = Field(default="")
    cybersixgill_api_key: str = Field(default="")
    shodan_api_key: str = Field(default="")

    @property
    def monitored_domain_list(self) -> list[str]:
        return [d.strip() for d in self.intel_monitored_domains.split(",") if d.strip()]

    @property
    def monitored_sector_list(self) -> list[str]:
        return [s.strip() for s in self.intel_monitored_sectors.split(",") if s.strip()]

    @property
    def enabled_agent_list(self) -> list[str]:
        return [a.strip() for a in self.intel_enabled_agents.split(",") if a.strip()]


threatlens_settings = ThreatLensSettings()
