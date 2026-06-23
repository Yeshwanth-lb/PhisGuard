"""SQLite DAO for ThreatLens tables.

Creates five new tables in the same database file as the main PhishGuard store.
The four existing tables (scans, pending_review, trusted_domains, feedback)
are never touched.
"""
import json
import os
import sqlite3
import threading

from app.threatlens.models import ActorCluster, IoCSet

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
