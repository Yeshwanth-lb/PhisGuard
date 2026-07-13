#!/usr/bin/env bash
# ============================================================================
# PhishGuard — Email-Bombing Defense: COMPLETE END-TO-END DEMO (presenter-paced)
# ----------------------------------------------------------------------------
# Runs the whole story in order, pausing between acts so you can talk and switch
# screens. Each act prints WHAT is about to happen and WHY before it runs.
#
#   Act 0  Preflight ........ app healthy? scripts present? Gmail reachable?
#   Act 1  Baseline ......... show a clean engine (active_attacks: 0)
#   Act 2  Fire the bomb .... realistic mixed flood hits the LIVE gateway :8025
#   Act 3  Detection ........ engine trips (active_attacks: 1) + dashboard banner
#   Act 4  Spoof quarantine . the fake .bank fails DMARC alignment -> phishing
#   Act 5  The payoff ....... real labeled mail in Gmail incl. [PhishGuard-Priority]
#   Act 6  Auto-release ..... the buffered noise releases itself ~45s later
#
# Screens to have open before you start:
#   • Dashboard : http://localhost:8000/
#   • Inbox     : Gmail for yeshwanthlb0@gmail.com
#
# Usage:   bash scripts/demo_e2e.sh            # default recipient ceo@company.com
#          RCPT=cfo@company.com bash scripts/demo_e2e.sh
#          NOPAUSE=1 bash scripts/demo_e2e.sh  # run straight through (rehearsal)
# ============================================================================

# NOTE: intentionally NOT using `set -e` — grep returning "no match" is normal
# here and must not abort the demo.
set -uo pipefail

# --- resolve repo root so relative paths (credentials/, scripts/) always work ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"
export PYTHONPATH=.

RCPT="${RCPT:-ceo@company.com}"
APP="http://localhost:8000"
CONTAINER="phishguard-app"

# --- colors -----------------------------------------------------------------
B=$'\033[1m'; G=$'\033[92m'; Y=$'\033[93m'; C=$'\033[96m'; R=$'\033[0m'; DIM=$'\033[2m'

say()  { printf '\n%s\n' "${B}${C}$*${R}"; }
note() { printf '%s\n' "${DIM}$*${R}"; }
ok()   { printf '%s\n' "${G}✓ $*${R}"; }
warn() { printf '%s\n' "${Y}! $*${R}"; }
rule() { printf '%s\n' "${DIM}────────────────────────────────────────────────────────────${R}"; }

pause() {
  [ "${NOPAUSE:-0}" = "1" ] && return 0
  printf '\n%s' "${Y}↵ press Enter to continue…${R}"
  read -r _ || true
  printf '\n'
}

health_attacks() {
  # Print the active_attacks count from /health (no auth needed).
  curl -s "$APP/health" 2>/dev/null \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['bombing_detector']['active_attacks'])" 2>/dev/null \
    || echo "?"
}

# ============================================================================
clear
cat <<BANNER
${B}${C}
  PhishGuard — Email-Bombing Defense
  Complete end-to-end demo
${R}
  An email bomb is a ${B}cover attack${R}: the attacker triggers ${B}one${R} real alert to you
  (an OTP, a "was this you?" login) and then buries it under ${B}thousands${R} of
  newsletter sign-ups so you never see it.

  PhishGuard's job: ${B}surface the one real alert, isolate the noise, drop nothing.${R}
  Target inbox for this run: ${B}${RCPT}${R}
BANNER
pause

# ── Act 0 — Preflight ───────────────────────────────────────────────────────
say "Act 0 — Preflight"
note "Confirming the gateway is up and the moving parts exist before we present."
rule
if curl -s -o /dev/null -w '%{http_code}' "$APP/health" | grep -q 200; then
  ok "engine healthy at $APP  (dashboard UI is the same host, path /)"
else
  warn "engine not responding at $APP — start the stack first (docker compose up -d)"; exit 1
fi
[ -f scripts/send_mixed_bomb.py ]       && ok "scripts/send_mixed_bomb.py present"       || { warn "missing send_mixed_bomb.py"; exit 1; }
[ -f scripts/demo_bombing_realmail.py ] && ok "scripts/demo_bombing_realmail.py present" || { warn "missing demo_bombing_realmail.py"; exit 1; }
docker ps --format '{{.Names}}' 2>/dev/null | grep -q "$CONTAINER" && ok "container '$CONTAINER' running" || warn "container '$CONTAINER' not found (log step may be quiet)"
pause

# ── Act 1 — Baseline ────────────────────────────────────────────────────────
say "Act 1 — Baseline: a calm engine"
note "Detection is per-recipient and real-time. With no flood, nothing is active."
rule
echo "${DIM}\$ curl -s $APP/health | python3 -m json.tool  (bombing_detector)${R}"
curl -s "$APP/health" 2>/dev/null | python3 -m json.tool 2>/dev/null | sed -n '/"bombing_detector"/,/}/p' | head -8
echo
ok "active_attacks right now: $(health_attacks)   ${DIM}(expect 0)${R}"
note "On the dashboard, the red 'inbox under attack' banner is absent."
pause

# ── Act 2 — Fire the bomb ───────────────────────────────────────────────────
say "Act 2 — Fire a realistic mixed bomb at the LIVE gateway (port 8025)"
note "25 messages: 15 newsletter sign-ups (the noise), 5 OTP/security codes,"
note "2 spoofed .bank alerts (the forgery), 3 genuine business mails — all to one inbox."
note "Phase 1 (the sign-up burst) is what trips detection; the rest arrives mid-attack."
rule
python3 scripts/send_mixed_bomb.py --rcpt "$RCPT"
ok "bomb delivered to the gateway"
pause

# ── Act 3 — Detection trips ─────────────────────────────────────────────────
say "Act 3 — The engine detects the flood"
note "Three windows run at once; ANY one trips it: Fast (5 sign-ups/30s),"
note "Standard (score ≥60 over 5 min: volume + sender-diversity), Slow-drip (100/hr)."
note "The score is language-independent — volume + diversity alone is enough."
rule
echo "${DIM}\$ curl -s $APP/health | python3 -m json.tool  (bombing_detector)${R}"
curl -s "$APP/health" 2>/dev/null | python3 -m json.tool 2>/dev/null | sed -n '/"bombing_detector"/,/"thresholds"/p' | head -7
echo
ATT="$(health_attacks)"
if [ "$ATT" != "0" ] && [ "$ATT" != "?" ]; then
  ok "active_attacks: $ATT   ${DIM}(detection fired — '$RCPT' is now in bombing mode)${R}"
else
  warn "active_attacks: $ATT — if 0, the recipient may have been mid-cooldown; re-run with a fresh RCPT"
fi
note "Switch to the dashboard: the red 'inbox under attack' banner is now showing."
note "A Slack alert also fired (once per inbox, suppressed for 10 min after)."
pause

# ── Act 4 — Spoof quarantined ───────────────────────────────────────────────
say "Act 4 — The spoofed bank is quarantined (this is the anti-spoof core)"
note "The two .bank alerts CLAIM a protected identity but carry no valid DKIM and"
note "don't align via SPF → 'spoofed_critical' → routed to phishing, never trusted."
note "Trust is earned by cryptography, not by the words in the From header."
rule
echo "${DIM}\$ docker logs --since 3m $CONTAINER | grep -E 'spoofed_critical|quarantin|phishing'${R}"
docker logs --since 3m "$CONTAINER" 2>&1 | grep -iE "spoofed_critical|quarantin|phishing" | tail -8 \
  || warn "no matching log lines yet (give it a second, or check the dashboard threat feed)"
echo
ok "the forgery was stopped — a real bank OTP, properly signed, would instead fast-track"
pause

# ── Act 5 — The payoff: real labeled mail, incl. instant priority ───────────
say "Act 5 — The payoff: surface the real alert NOW, label the noise"
note "This delivers REAL mail to Gmail (yeshwanthlb0@gmail.com), prefixed [PG-DEMO]:"
note "  • an AUTHENTICATED bank OTP (DKIM-aligned) → delivered instantly  [PhishGuard-Priority]"
note "  • a newsletter (structural bulk signals)   → [Possible Bombing Noise]"
note "  • a known business contact                 → [Received During Mail Bomb]"
note "Only the bank OTP's signature is simulated offline — we can't forge a real bank key."
rule
python3 scripts/demo_bombing_realmail.py
echo
ok "delivered — SWITCH TO GMAIL and click the ${B}PhishGuard-Priority${R}${G} label${R}"
note "The OTP the attacker tried to bury is sitting at the top, tagged and instant."
pause

# ── Act 6 — Auto-release of the buffered noise ──────────────────────────────
say "Act 6 — Nothing is held for a human: the noise releases itself"
note "Everything buffered in Act 2 sits in a crash-safe SQLite (WAL) buffer and is"
note "auto-released LABELED by the worker once the analysis window passes (~45s here)."
note "Atomic claim before delivery → never double-sent; a crashed claim is retried."
rule
WIN="$(grep -E '^BOMBING_ANALYSIS_WINDOW_SECS' .env 2>/dev/null | cut -d= -f2)"
note "Current release window: ${WIN:-300}s (set in .env; production default is 300)."
echo "${DIM}\$ docker logs --since 3m $CONTAINER | grep -E 'bombing_release_cycle|released'${R}"
docker logs --since 3m "$CONTAINER" 2>&1 | grep -iE "bombing_release_cycle|released" | tail -5 \
  || note "(not released yet — wait until the window passes, then refresh Gmail)"
echo
ok "after the window, the Act-2 flood appears in Gmail labeled [Possible Bombing Noise] / [Received During Mail Bomb]"
pause

# ── Recap ───────────────────────────────────────────────────────────────────
say "Recap — the asymmetric defense"
cat <<RECAP
  ${B}Old way:${R}  detect the bomb → guess importance from the subject → park the rest
            in a human queue (which buries the OTP a second time).

  ${B}Our way:${R}  detect across 3 time-scales → verify ${B}who actually sent it${R} (DKIM/SPF
            alignment, not keywords) → deliver that ${B}instantly${R} → buffer-then-auto-release
            the noise, labeled.

  ${G}${B}Nothing dropped. Nothing held for a human. Nothing trusted on forgeable evidence.${R}
RECAP
echo
ok "demo complete"
