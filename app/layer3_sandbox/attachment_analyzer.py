"""Layer 3 - Attachment static analysis.

The browser sandbox (sandbox_runner) only detonates URLs. Malicious attachments
(macro-laden Office docs, executables disguised with double extensions, archives
hiding payloads) are a whole separate delivery vector it can't see. This module
statically inspects attachment *content* — no execution — using oletools' olevba
for real VBA macro extraction, plus signature/extension/archive heuristics.

Scoring is deliberately two-tier so it can run on ALL attachment-bearing mail
without false-positiving legitimate business documents:

  phishing  (>= 0.65) — UNAMBIGUOUS malware: executable/script file types,
                        double extensions (invoice.pdf.exe), or macros that
                        auto-execute / carry suspicious IOCs. These are never
                        legitimate, so the pipeline lets them override even an
                        authenticated-sender fast-pass (account-takeover defense).
  suspicious(>= 0.40) — macro present but no auto-exec/suspicious indicator, or a
                        password-protected archive (a known inspection-evasion
                        trick). Finance/ops teams send benign macro sheets all the
                        time, so this only nudges the blend, never solo-condemns.
  clean               — nothing notable.

Everything is best-effort and fail-open per attachment: a parse error on one file
never blocks the others or the pipeline.
"""
from __future__ import annotations

import asyncio
import os
import zipfile
from email import message_from_bytes
from email.header import decode_header, make_header
from email.policy import compat32
from io import BytesIO

import structlog

logger = structlog.get_logger()

PHISHING_THRESHOLD = 0.65
SUSPICIOUS_THRESHOLD = 0.40

# File types that are executable/scriptable and essentially never a legitimate
# email attachment. A final extension in this set is treated as malware.
DANGEROUS_EXTS = {
    "exe", "scr", "pif", "com", "bat", "cmd", "msi", "cpl", "scf", "reg",
    "js", "jse", "vbs", "vbe", "wsf", "wsh", "hta", "ps1", "ps1xml", "psc1",
    "jar", "lnk", "iso", "img", "vhd", "vhdx", "application", "gadget",
}

# Extensions that commonly appear as the *first* part of a double extension
# (attacker disguises payload.exe as invoice.pdf.exe). Presence of one of these
# before a dangerous extension escalates the finding.
DECOY_EXTS = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg",
              "jpeg", "png", "gif", "zip", "csv", "htm", "html"}

# Office formats olevba can inspect for VBA macros.
MACRO_CAPABLE_EXTS = {"doc", "docm", "dot", "dotm", "xls", "xlsm", "xlsb",
                      "xlt", "xltm", "ppt", "pptm", "pot", "potm", "xla", "xlam"}

# Cap per-file work — olevba on a huge file could stall the event loop thread.
DEFAULT_MAX_SCAN_BYTES = 25 * 1024 * 1024  # 25 MB


def _decode_filename(raw_name: str) -> str:
    try:
        return str(make_header(decode_header(str(raw_name))))
    except Exception:
        return str(raw_name)


def _ext_parts(filename: str) -> list[str]:
    """Lowercased extension tokens of a filename, e.g. invoice.pdf.exe -> [pdf, exe]."""
    base = os.path.basename(filename or "").strip().lower()
    parts = base.split(".")
    return parts[1:] if len(parts) > 1 else []


def _iter_attachment_bytes(raw_eml: bytes):
    """Yield (filename, content_type, payload_bytes) for each attachment part.
    Re-parses the raw email because the pipeline's parsed dict keeps only
    attachment metadata (hash/size), not the bytes."""
    try:
        msg = message_from_bytes(raw_eml, policy=compat32)
    except Exception as exc:
        logger.warning("attachment_msg_parse_failed", error=str(exc))
        return
    for part in msg.walk():
        try:
            disposition = part.get_content_disposition()
        except Exception:
            disposition = None
        if disposition not in ("attachment", "inline"):
            continue
        filename = _decode_filename(part.get_filename() or "")
        if not filename:
            continue
        try:
            payload = part.get_payload(decode=True)
        except Exception:
            continue
        if not isinstance(payload, (bytes, bytearray)):
            continue
        try:
            ctype = part.get_content_type()
        except Exception:
            ctype = "application/octet-stream"
        yield filename, ctype, bytes(payload)


def _scan_macros(filename: str, payload: bytes) -> tuple[float, list[str]]:
    """Use olevba to detect + classify VBA macros. Returns (score, findings)."""
    try:
        from oletools.olevba import VBA_Parser
    except Exception:
        logger.warning("olevba_unavailable")
        return 0.0, []
    findings: list[str] = []
    score = 0.0
    vparser = None
    try:
        vparser = VBA_Parser(filename, data=payload)
        if not vparser.detect_vba_macros():
            return 0.0, []
        findings.append("vba_macros_present")
        score = 0.5  # macro present but not yet shown to be malicious
        try:
            results = vparser.analyze_macros()  # list of (type, keyword, description)
        except Exception:
            results = []
        flagged = set()
        for rtype, keyword, _desc in results or []:
            t = (rtype or "").lower()
            if t in ("autoexec", "suspicious", "ioc"):
                flagged.add(f"{t}:{keyword}")
        if flagged:
            # auto-executing or suspicious-API macros are the malicious signal
            findings.extend(sorted(flagged)[:8])
            score = 0.9
    except Exception as exc:
        logger.info("macro_scan_error", filename=filename[:60], error=str(exc)[:80])
    finally:
        if vparser is not None:
            try:
                vparser.close()
            except Exception:
                pass
    return score, findings


def _scan_archive(payload: bytes) -> tuple[float, list[str]]:
    """Best-effort zip introspection: dangerous files inside, or an encrypted
    archive (a common way to hide payloads from scanners)."""
    findings: list[str] = []
    score = 0.0
    try:
        zf = zipfile.ZipFile(BytesIO(payload))
    except Exception:
        return 0.0, []  # not a zip / unreadable — nothing to say
    try:
        for info in zf.infolist():
            # flag_bits & 0x1 => encrypted entry
            if info.flag_bits & 0x1:
                findings.append("encrypted_archive")
                score = max(score, 0.6)
            inner_exts = _ext_parts(info.filename)
            if inner_exts and inner_exts[-1] in DANGEROUS_EXTS:
                findings.append(f"archive_contains:{os.path.basename(info.filename)[:50]}")
                score = max(score, 0.85)
    except Exception as exc:
        logger.info("archive_scan_error", error=str(exc)[:80])
    finally:
        try:
            zf.close()
        except Exception:
            pass
    return score, findings


def _analyze_one(filename: str, ctype: str, payload: bytes, max_bytes: int) -> dict:
    """Static checks for a single attachment. Returns per-file result dict."""
    exts = _ext_parts(filename)
    final_ext = exts[-1] if exts else ""
    score = 0.0
    findings: list[str] = []

    # 1. Dangerous executable/script file type (by final extension).
    if final_ext in DANGEROUS_EXTS:
        score = max(score, 0.95)
        findings.append(f"dangerous_ext:{final_ext}")
        # 2. Double extension (invoice.pdf.exe) — even stronger signal.
        if len(exts) >= 2 and exts[-2] in DECOY_EXTS:
            score = max(score, 0.97)
            findings.append(f"double_ext:{'.'.join(exts[-2:])}")

    if len(payload) > max_bytes:
        findings.append(f"skipped_deep_scan_size:{len(payload)}")
    else:
        # 3. Office macro analysis.
        if final_ext in MACRO_CAPABLE_EXTS or "officedocument" in ctype or "ms-office" in ctype:
            m_score, m_find = _scan_macros(filename, payload)
            score = max(score, m_score)
            findings.extend(m_find)
        # 4. Archive introspection.
        if final_ext in ("zip",) or ctype in ("application/zip", "application/x-zip-compressed"):
            a_score, a_find = _scan_archive(payload)
            score = max(score, a_score)
            findings.extend(a_find)

    if score >= PHISHING_THRESHOLD:
        verdict = "phishing"
    elif score >= SUSPICIOUS_THRESHOLD:
        verdict = "suspicious"
    else:
        verdict = "clean"
    return {
        "filename": filename,
        "content_type": ctype,
        "size": len(payload),
        "score": round(score, 3),
        "verdict": verdict,
        "findings": findings,
    }


def _analyze_sync(raw_eml: bytes, max_bytes: int) -> dict:
    per_file: list[dict] = []
    for filename, ctype, payload in _iter_attachment_bytes(raw_eml):
        try:
            per_file.append(_analyze_one(filename, ctype, payload, max_bytes))
        except Exception as exc:
            logger.info("attachment_analyze_error", filename=filename[:60], error=str(exc)[:80])
    if not per_file:
        return {"verdict": "skipped", "score": 0.0, "reason": "no_attachments",
                "attachments": []}
    worst = max(per_file, key=lambda a: a["score"])
    score = worst["score"]
    if score >= PHISHING_THRESHOLD:
        verdict = "phishing"
    elif score >= SUSPICIOUS_THRESHOLD:
        verdict = "suspicious"
    else:
        verdict = "clean"
    findings = [f"{a['filename']}: {', '.join(a['findings'])}"
                for a in per_file if a["findings"]]
    return {
        "verdict": verdict,
        "score": score,
        "worst_attachment": worst["filename"],
        "findings": findings,
        "attachments": per_file,
    }


async def analyze_attachments(raw_eml: bytes, settings=None) -> dict:
    """Statically analyze all attachments in a raw email. Never raises —
    returns a verdict dict (verdict: phishing|suspicious|clean|skipped).
    olevba/zip work is offloaded to a thread so it doesn't block the loop."""
    if not raw_eml:
        return {"verdict": "skipped", "score": 0.0, "reason": "no_raw", "attachments": []}
    max_bytes = getattr(settings, "max_attachment_scan_bytes", DEFAULT_MAX_SCAN_BYTES) if settings else DEFAULT_MAX_SCAN_BYTES
    try:
        result = await asyncio.to_thread(_analyze_sync, raw_eml, max_bytes)
    except Exception as exc:
        logger.warning("attachment_analysis_failed", error=str(exc)[:120])
        return {"verdict": "error", "score": 0.0, "error": str(exc)[:120], "attachments": []}
    if result.get("attachments"):
        logger.info("attachment_analysis", verdict=result["verdict"],
                    score=result["score"], n=len(result["attachments"]))
    return result
