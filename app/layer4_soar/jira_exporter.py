"""Layer 4 - Jira exporter."""
import base64

import structlog

logger = structlog.get_logger()


def _build_issue(doc, project, kind):
    a = doc.get("parsed") or {}
    v = doc.get("verdict", "x")
    c = doc.get("confidence", 0.0)
    bl = doc.get("blocked_at") or "n/a"
    snd = a.get("from_header") or "?"
    sub = a.get("subject") or "(none)"
    links = (a.get("urls") or [])[:5]
    summary = "PhishGuard " + v.upper() + " | " + snd + " | " + sub[:60]
    L = [
        "Verdict: " + v.upper() + " (conf " + str(round(c * 100)) + "%)",
        "Blocked at: " + str(bl),
        "Sender: " + snd,
        "Subject: " + sub,
        "Link count: " + str(len(links)),
    ]
    if links:
        L.append("Top links: " + ", ".join(links))
    l3 = doc.get("l3") or {}
    if l3:
        L.append("Sandbox final: " + (l3.get("final_url") or "n/a"))
        L.append("Sandbox title: " + (l3.get("title") or "n/a"))
        pf = l3.get("page_findings") or []
        of = l3.get("ocr_findings") or []
        if pf:
            L.append("Page findings: " + ", ".join(map(str, pf)))
        if of:
            L.append("OCR findings: " + ", ".join(map(str, of)))
    body = chr(10).join(L)
    return {
        "fields": {
            "project": {"key": project},
            "issuetype": {"name": kind},
            "summary": summary,
            "description": {
                "type": "doc",
                "version": 1,
                "content": [{
                    "type": "paragraph",
                    "content": [{"type": "text", "text": body}],
                }],
            },
            "labels": ["phishguard", "verdict-" + v, "layer-" + str(bl)],
        }
    }


async def export_to_jira(doc, settings):
    base = getattr(settings, "jira_base_url", "") or ""
    em = getattr(settings, "jira_email", "") or ""
    tk = getattr(settings, "jira_api_token", "") or ""
    pr = getattr(settings, "jira_project_key", "") or ""
    kind = getattr(settings, "jira_issue_type", "Task") or "Task"
    if not (base and em and tk and pr):
        return False
    v = doc.get("verdict", "")
    if v not in ("phishing", "suspicious"):
        return False
    try:
        import httpx
    except ImportError:
        return False
    try:
        creds = (em + ":" + tk).encode("utf-8")
        auth = "Basic " + base64.b64encode(creds).decode("ascii")
        sl = chr(47)
        url = base.rstrip(sl) + sl + "rest" + sl + "api" + sl + "3" + sl + "issue"
        body = _build_issue(doc, pr, kind)
        h = {"Authorization": auth, "Content-Type": "application/json", "Accept": "application/json"}
        async with httpx.AsyncClient() as client:
            r = await client.post(url, json=body, headers=h, timeout=15)
            r.raise_for_status()
            data = r.json()
            logger.info("jira_ticket_created", key=data.get("key"))
            return True
    except Exception as exc:
        logger.warning("jira_export_error", error=str(exc))
        return False


async def probe_jira(settings):
    base = getattr(settings, "jira_base_url", "") or ""
    em = getattr(settings, "jira_email", "") or ""
    tk = getattr(settings, "jira_api_token", "") or ""
    pr = getattr(settings, "jira_project_key", "") or ""
    if not (base and em and tk and pr):
        return {"configured": False, "reachable": False, "reason": "not_configured"}
    try:
        import httpx
        creds = (em + ":" + tk).encode("utf-8")
        auth = "Basic " + base64.b64encode(creds).decode("ascii")
        sl = chr(47)
        url = base.rstrip(sl) + sl + "rest" + sl + "api" + sl + "3" + sl + "myself"
        h = {"Authorization": auth, "Accept": "application/json"}
        async with httpx.AsyncClient() as client:
            r = await client.get(url, headers=h, timeout=10)
            ok = r.status_code == 200
            return {"configured": True, "reachable": ok, "status": r.status_code, "project": pr}
    except Exception as exc:
        return {"configured": True, "reachable": False, "error": str(exc)}
