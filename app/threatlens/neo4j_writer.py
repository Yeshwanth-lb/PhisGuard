"""Writes ThreatLens graph data to Neo4j for visualization via Neovis.js.

Called after every profiling cycle. Upserts nodes and relationships so
the Neo4j graph always reflects current profile state.

Neo4j Browser: http://localhost:7474
  Login: settings.neo4j_user / settings.neo4j_password (NEO4J_USER / NEO4J_PASSWORD
  in .env — defaults to neo4j / changeme123, matching docker-compose's NEO4J_AUTH).

Useful Cypher queries in the browser:
  // All threat clusters
  MATCH (c:ThreatCluster) RETURN c

  // All connections
  MATCH (a:ThreatCluster)-[r]->(b:ThreatCluster) RETURN a,r,b

  // Shared infrastructure only
  MATCH (a)-[r:SHARED_IP|SHARED_DOMAIN]->(b) RETURN a,r,b

  // High-severity clusters and their connections
  MATCH (a:ThreatCluster)-[r]->(b:ThreatCluster)
  WHERE a.severity IN ['critical','high']
  RETURN a,r,b
"""
from __future__ import annotations

import structlog

from app.config import settings

logger = structlog.get_logger()

# Relationship type map: edge type → Cypher relationship type
_REL_TYPES = {
    "shared_ip":     "SHARED_IP",
    "shared_domain": "SHARED_DOMAIN",
    "shared_ttps":   "SHARED_TTPS",
}


async def push_graph(nodes: list[dict], edges: list[dict]) -> dict:
    """Upsert all cluster nodes and relationships into Neo4j.

    Returns a summary dict. Silently skips if Neo4j is unavailable.
    """
    try:
        from neo4j import AsyncGraphDatabase
    except ImportError:
        logger.warning("neo4j_driver_not_installed")
        return {"skipped": True, "reason": "neo4j package not installed"}

    try:
        driver = AsyncGraphDatabase.driver(
            settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password)
        )
        await driver.verify_connectivity()
    except Exception as exc:
        logger.warning("neo4j_unavailable", error=str(exc)[:80])
        return {"skipped": True, "reason": str(exc)[:80]}

    nodes_written = 0
    edges_written = 0

    try:
        async with driver.session() as session:
            # Clear existing ThreatLens data (full refresh each cycle)
            await session.run("MATCH (c:ThreatCluster) DETACH DELETE c")

            # Upsert cluster nodes
            for n in nodes:
                await session.run("""
                    MERGE (c:ThreatCluster {id: $id})
                    SET c.full_id       = $full_id,
                        c.label         = $label,
                        c.short_label   = $short_label,
                        c.intent        = $intent,
                        c.group         = $group,
                        c.group_color   = $group_color,
                        c.severity      = $severity,
                        c.confidence    = $confidence,
                        c.member_count  = $member_count,
                        c.summary       = $summary,
                        c.domains       = $domains,
                        c.ttp_ids       = $ttp_ids,
                        c.surface_zones = $surface_zones
                """, **n)
                nodes_written += 1

            # Create relationships
            for e in edges:
                rel_type = _REL_TYPES.get(e["type"], "RELATED_TO")
                await session.run(f"""
                    MATCH (a:ThreatCluster {{id: $from_id}}),
                          (b:ThreatCluster {{id: $to_id}})
                    MERGE (a)-[r:{rel_type}]->(b)
                    SET r.label  = $label,
                        r.weight = $weight,
                        r.type   = $type
                """, from_id=e["from"], to_id=e["to"],
                     label=e.get("label",""), weight=e.get("weight",0.5),
                     type=e["type"])
                edges_written += 1

            # Create indexes for fast lookup
            await session.run("CREATE INDEX threat_cluster_id IF NOT EXISTS FOR (c:ThreatCluster) ON (c.id)")
            await session.run("CREATE INDEX threat_cluster_severity IF NOT EXISTS FOR (c:ThreatCluster) ON (c.severity)")

    finally:
        await driver.close()

    logger.info(
        "neo4j_push_done",
        nodes=nodes_written,
        edges=edges_written,
        uri=settings.neo4j_uri,
    )
    return {"nodes": nodes_written, "edges": edges_written}
