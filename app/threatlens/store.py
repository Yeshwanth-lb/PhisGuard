"""SQLite DAO for ThreatLens tables.

Creates five new tables in the same database file as the main PhishGuard store.
The four existing tables (scans, pending_review, trusted_domains, feedback)
are never touched.
"""
import json
import os
import sqlite3
import threading

from app.threatlens.models import ActorCluster, AdversaryProfile, Finding, IoCSet, OrgThreatAssessment, TTP, CorroboratedClaim, TTPObservation

_DB_PATH = os.environ.get('PHISHGUARD_DB_PATH', 'data/phishguard.db')
_lock = threading.Lock()


def _conn(db_path: str) -> sqlite3.Connection:
    parent = os.path.dirname(os.path.abspath(db_path))
    os.makedirs(parent, exist_ok=True)
    c = sqlite3.connect(db_path, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


def init_db(db_path: str = _DB_PATH) -> None:
    """Create all five ThreatLens tables. Safe to call multiple times (idempotent)."""
    with _lock:
        c = _conn(db_path)
        try:
            c.execute("""
                CREATE TABLE IF NOT EXISTS actor_clusters (
                    id              TEXT PRIMARY KEY,
                    created_at      REAL NOT NULL,
                    updated_at      REAL NOT NULL,
                    first_seen      REAL NOT NULL,
                    last_seen       REAL NOT NULL,
                    member_scan_ids TEXT NOT NULL DEFAULT '[]',
                    dominant_intent TEXT,
                    ioc_json        TEXT NOT NULL DEFAULT '{}',
                    target_json     TEXT NOT NULL DEFAULT '{}',
                    signature_json  TEXT NOT NULL DEFAULT '{}',
                    status          TEXT NOT NULL DEFAULT 'active'
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS actor_profiles (
                    id                  TEXT PRIMARY KEY,
                    cluster_id          TEXT NOT NULL,
                    generated_at        REAL NOT NULL,
                    assessed_identity   TEXT,
                    suspected_apt       TEXT,
                    assessed_intent     TEXT,
                    severity            TEXT,
                    confidence          TEXT,
                    ttp_json            TEXT NOT NULL DEFAULT '[]',
                    surface_zones_json  TEXT NOT NULL DEFAULT '[]',
                    segments_json       TEXT NOT NULL DEFAULT '[]',
                    evidence_json       TEXT NOT NULL DEFAULT '[]',
                    summary             TEXT,
                    model               TEXT,
                    FOREIGN KEY (cluster_id) REFERENCES actor_clusters(id)
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS intel_sources (
                    id              TEXT PRIMARY KEY,
                    cluster_id      TEXT,
                    agent           TEXT,
                    source_url      TEXT,
                    source_title    TEXT,
                    fetched_at      REAL,
                    finding_json    TEXT,
                    confidence      TEXT
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS ttp_observations (
                    id              TEXT PRIMARY KEY,
                    cluster_id      TEXT,
                    attack_id       TEXT,
                    tactic          TEXT,
                    surface_zone    TEXT,
                    evidence_ref    TEXT,
                    observed_at     REAL NOT NULL
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS org_threat_assessment (
                    id                      TEXT PRIMARY KEY,
                    generated_at            REAL NOT NULL,
                    adversary_landscape     TEXT,
                    surface_pressure_json   TEXT NOT NULL DEFAULT '{}',
                    sector_pressure_json    TEXT NOT NULL DEFAULT '{}',
                    strategic_intent        TEXT,
                    top_campaigns_json      TEXT NOT NULL DEFAULT '[]',
                    source_profile_ids      TEXT NOT NULL DEFAULT '[]',
                    confidence              TEXT,
                    evidence_json           TEXT NOT NULL DEFAULT '[]',
                    summary                 TEXT,
                    model                   TEXT
                )
            """)
            c.commit()
        finally:
            c.close()


def upsert_cluster(cluster: ActorCluster, db_path: str = _DB_PATH) -> None:
    """Insert or update a cluster. On update, created_at is preserved from the DB."""
    with _lock:
        c = _conn(db_path)
        try:
            row = c.execute(
                "SELECT created_at FROM actor_clusters WHERE id = ?", (cluster.id,)
            ).fetchone()
            created_at = row["created_at"] if row else cluster.created_at

            c.execute("""
                INSERT OR REPLACE INTO actor_clusters
                    (id, created_at, updated_at, first_seen, last_seen,
                     member_scan_ids, dominant_intent, ioc_json, target_json,
                     signature_json, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cluster.id,
                created_at,
                cluster.updated_at,
                cluster.first_seen,
                cluster.last_seen,
                json.dumps(cluster.member_scan_ids),
                cluster.dominant_intent,
                json.dumps(cluster.iocs.model_dump()),
                json.dumps(cluster.targets),
                json.dumps(cluster.signature),
                cluster.status,
            ))
            c.commit()
        finally:
            c.close()


def _row_to_cluster(row: sqlite3.Row) -> ActorCluster:
    return ActorCluster(
        id=row["id"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        member_scan_ids=json.loads(row["member_scan_ids"] or "[]"),
        dominant_intent=row["dominant_intent"],
        iocs=IoCSet(**json.loads(row["ioc_json"] or "{}")),
        targets=json.loads(row["target_json"] or "{}"),
        signature=json.loads(row["signature_json"] or "{}"),
        status=row["status"],
    )


def get_cluster(cluster_id: str, db_path: str = _DB_PATH) -> ActorCluster | None:
    with _lock:
        c = _conn(db_path)
        try:
            row = c.execute(
                "SELECT * FROM actor_clusters WHERE id = ?", (cluster_id,)
            ).fetchone()
            return _row_to_cluster(row) if row else None
        finally:
            c.close()


def get_active_clusters(db_path: str = _DB_PATH) -> list[ActorCluster]:
    with _lock:
        c = _conn(db_path)
        try:
            rows = c.execute(
                "SELECT * FROM actor_clusters WHERE status = 'active' ORDER BY last_seen DESC"
            ).fetchall()
            return [_row_to_cluster(r) for r in rows]
        finally:
            c.close()


def get_all_clusters(db_path: str = _DB_PATH) -> list[ActorCluster]:
    """Return all non-merged clusters (active + dormant)."""
    with _lock:
        c = _conn(db_path)
        try:
            rows = c.execute(
                "SELECT * FROM actor_clusters WHERE status != 'merged' ORDER BY last_seen DESC"
            ).fetchall()
            return [_row_to_cluster(r) for r in rows]
        finally:
            c.close()


# ---------------------------------------------------------------------------
# Profile CRUD
# ---------------------------------------------------------------------------

def upsert_profile(profile: AdversaryProfile, db_path: str = _DB_PATH) -> None:
    """Insert or replace the profile for a cluster (one current profile per cluster)."""
    with _lock:
        c = _conn(db_path)
        try:
            # Keep only one profile per cluster — delete any existing row first
            c.execute("DELETE FROM actor_profiles WHERE cluster_id = ?", (profile.cluster_id,))
            c.execute("""
                INSERT INTO actor_profiles
                    (id, cluster_id, generated_at, assessed_identity, suspected_apt,
                     assessed_intent, severity, confidence, ttp_json, surface_zones_json,
                     segments_json, evidence_json, summary, model)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                profile.id,
                profile.cluster_id,
                profile.generated_at,
                profile.assessed_identity,
                profile.suspected_apt,
                profile.assessed_intent,
                profile.severity,
                profile.confidence,
                json.dumps([t.model_dump() for t in profile.ttps]),
                json.dumps(profile.surface_zones),
                json.dumps(profile.segments),
                json.dumps([e.model_dump() for e in profile.evidence]),
                profile.summary,
                profile.model,
            ))
            c.commit()
        finally:
            c.close()


def _row_to_profile(row: sqlite3.Row) -> AdversaryProfile:
    ttps = [TTP(**t) for t in json.loads(row["ttp_json"] or "[]")]
    evidence = []
    for e in json.loads(row["evidence_json"] or "[]"):
        evidence.append(Finding(
            agent=e.get("agent", "profiler"),
            claim=e.get("claim", ""),
            source_url=e.get("source_url"),
            source_title=e.get("source_title"),
            confidence=e.get("confidence", "low"),
            raw=e.get("raw", {}),
        ))
    return AdversaryProfile(
        id=row["id"],
        cluster_id=row["cluster_id"],
        generated_at=row["generated_at"],
        assessed_identity=row["assessed_identity"] or "Unattributed Cluster",
        suspected_apt=row["suspected_apt"],
        assessed_intent=row["assessed_intent"] or "unknown",
        severity=row["severity"] or "low",
        confidence=row["confidence"] or "speculative",
        ttps=ttps,
        surface_zones=json.loads(row["surface_zones_json"] or "[]"),
        segments=json.loads(row["segments_json"] or "[]"),
        claims=[],
        evidence=evidence,
        summary=row["summary"] or "",
        model=row["model"] or "",
    )


def get_profile(profile_id: str, db_path: str = _DB_PATH) -> AdversaryProfile | None:
    with _lock:
        c = _conn(db_path)
        try:
            row = c.execute(
                "SELECT * FROM actor_profiles WHERE id = ?", (profile_id,)
            ).fetchone()
            return _row_to_profile(row) if row else None
        finally:
            c.close()


def get_profile_by_cluster(cluster_id: str, db_path: str = _DB_PATH) -> AdversaryProfile | None:
    with _lock:
        c = _conn(db_path)
        try:
            row = c.execute(
                "SELECT * FROM actor_profiles WHERE cluster_id = ? ORDER BY generated_at DESC LIMIT 1",
                (cluster_id,)
            ).fetchone()
            return _row_to_profile(row) if row else None
        finally:
            c.close()


def get_profiles(db_path: str = _DB_PATH) -> list[AdversaryProfile]:
    with _lock:
        c = _conn(db_path)
        try:
            rows = c.execute(
                "SELECT * FROM actor_profiles ORDER BY generated_at DESC"
            ).fetchall()
            return [_row_to_profile(r) for r in rows]
        finally:
            c.close()


# ---------------------------------------------------------------------------
# TTP Observations CRUD
# ---------------------------------------------------------------------------

def upsert_ttp_observation(obs: TTPObservation, db_path: str = _DB_PATH) -> None:
    with _lock:
        c = _conn(db_path)
        try:
            c.execute("""
                INSERT OR REPLACE INTO ttp_observations
                    (id, cluster_id, attack_id, tactic, surface_zone, evidence_ref, observed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                obs.id,
                obs.cluster_id,
                obs.attack_id,
                obs.tactic,
                obs.surface_zone,
                obs.evidence_ref,
                obs.observed_at,
            ))
            c.commit()
        finally:
            c.close()


def get_ttp_observations(cluster_id: str, db_path: str = _DB_PATH) -> list[TTPObservation]:
    with _lock:
        c = _conn(db_path)
        try:
            rows = c.execute(
                "SELECT * FROM ttp_observations WHERE cluster_id = ? ORDER BY observed_at DESC",
                (cluster_id,)
            ).fetchall()
            return [
                TTPObservation(
                    id=r["id"],
                    cluster_id=r["cluster_id"],
                    attack_id=r["attack_id"],
                    tactic=r["tactic"],
                    surface_zone=r["surface_zone"],
                    evidence_ref=r["evidence_ref"],
                    observed_at=r["observed_at"],
                )
                for r in rows
            ]
        finally:
            c.close()


def get_all_ttp_observations(db_path: str = _DB_PATH) -> list[TTPObservation]:
    """Return all TTP observations across all clusters."""
    with _lock:
        c = _conn(db_path)
        try:
            rows = c.execute(
                "SELECT * FROM ttp_observations ORDER BY observed_at DESC"
            ).fetchall()
            return [
                TTPObservation(
                    id=r["id"],
                    cluster_id=r["cluster_id"],
                    attack_id=r["attack_id"],
                    tactic=r["tactic"],
                    surface_zone=r["surface_zone"],
                    evidence_ref=r["evidence_ref"],
                    observed_at=r["observed_at"],
                )
                for r in rows
            ]
        finally:
            c.close()


# ---------------------------------------------------------------------------
# Org Threat Assessment CRUD
# ---------------------------------------------------------------------------

def upsert_org_assessment(assessment: OrgThreatAssessment, db_path: str = _DB_PATH) -> None:
    """Persist assessment. Keeps only the latest 12 rows."""
    with _lock:
        c = _conn(db_path)
        try:
            c.execute("""
                INSERT OR REPLACE INTO org_threat_assessment
                    (id, generated_at, adversary_landscape, surface_pressure_json,
                     sector_pressure_json, strategic_intent, top_campaigns_json,
                     source_profile_ids, confidence, evidence_json, summary, model)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                assessment.id,
                assessment.generated_at,
                assessment.adversary_landscape,
                json.dumps(assessment.surface_pressure),
                json.dumps(assessment.sector_pressure),
                assessment.strategic_intent,
                json.dumps(assessment.top_campaigns),
                json.dumps(assessment.source_profile_ids),
                assessment.confidence,
                json.dumps([e.model_dump() for e in assessment.evidence]),
                assessment.summary,
                assessment.model,
            ))
            # Prune to latest 12
            c.execute("""
                DELETE FROM org_threat_assessment WHERE id NOT IN (
                    SELECT id FROM org_threat_assessment ORDER BY generated_at DESC LIMIT 12
                )
            """)
            c.commit()
        finally:
            c.close()


def get_latest_org_assessment(db_path: str = _DB_PATH) -> OrgThreatAssessment | None:
    with _lock:
        c = _conn(db_path)
        try:
            row = c.execute(
                "SELECT * FROM org_threat_assessment ORDER BY generated_at DESC LIMIT 1"
            ).fetchone()
            if not row:
                return None
            return OrgThreatAssessment(
                id=row["id"],
                generated_at=row["generated_at"],
                adversary_landscape=row["adversary_landscape"] or "",
                surface_pressure=json.loads(row["surface_pressure_json"] or "{}"),
                sector_pressure=json.loads(row["sector_pressure_json"] or "{}"),
                strategic_intent=row["strategic_intent"] or "unknown",
                top_campaigns=json.loads(row["top_campaigns_json"] or "[]"),
                source_profile_ids=json.loads(row["source_profile_ids"] or "[]"),
                confidence=row["confidence"] or "speculative",
                evidence=[],
                summary=row["summary"] or "",
                model=row["model"] or "",
            )
        finally:
            c.close()


# ---------------------------------------------------------------------------
# Profile feedback
# ---------------------------------------------------------------------------

def save_profile_feedback(
    profile_id: str,
    rating: str,
    notes: str = "",
    submitted_by: str = "soc",
    db_path: str = _DB_PATH,
) -> bool:
    """Save analyst rating for an adversary profile."""
    import uuid as _uuid
    with _lock:
        c = _conn(db_path)
        try:
            import time as _time
            c.execute("""
                CREATE TABLE IF NOT EXISTS profile_feedback (
                    id TEXT PRIMARY KEY,
                    profile_id TEXT NOT NULL,
                    rating TEXT NOT NULL,
                    notes TEXT DEFAULT '',
                    submitted_at REAL NOT NULL,
                    submitted_by TEXT DEFAULT 'soc'
                )
            """)
            c.execute("""
                INSERT INTO profile_feedback
                    (id, profile_id, rating, notes, submitted_at, submitted_by)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (_uuid.uuid4().hex, profile_id, rating, notes, _time.time(), submitted_by))
            c.commit()
            return True
        except Exception:
            return False
        finally:
            c.close()
