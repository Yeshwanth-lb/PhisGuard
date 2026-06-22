"""PhishGuard SMTP Gateway — procedurally generated 9-email demo.

Every run produces genuinely unique emails — randomised names, companies,
domains, amounts, urgency levels and phrasing — so the ML model never sees
the same feature vector twice.

Usage:
    python3 scripts/test_smtp_gateway.py              # fresh random run
    python3 scripts/test_smtp_gateway.py --seed 42    # reproducible run
    python3 scripts/test_smtp_gateway.py --count 3    # emails per category
"""
import argparse
import random
import smtplib
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

PHISHGUARD_HOST = "localhost"
PHISHGUARD_PORT = 8025
RECIPIENT       = "yeshwanthlb0@gmail.com"

RESET  = "\033[0m"; BOLD = "\033[1m"
GREEN  = "\033[92m"; YELLOW = "\033[93m"; RED = "\033[91m"; CYAN = "\033[96m"


# ── Word banks ───────────────────────────────────────────────────────────────

_FIRST  = ["Alice","Bob","Sarah","Mike","Priya","James","Emma","David","Ravi","Chen","Omar","Nina"]
_LAST   = ["Smith","Johnson","Patel","Kumar","Chen","Williams","Brown","Kim","Garcia","Müller"]
_DEPT   = ["Engineering","Product","HR","Finance","DevOps","Security","Sales","Design"]
_CO     = ["Acme","Nexus","Vertex","Pulse","Orbit","Crest","Sigma","Apex","Forge","Delta"]
_CO_SFX = ["Corp","Inc","Tech","Systems","Solutions","Labs","Group","HQ"]
_DAY    = ["Monday","Tuesday","Wednesday","Thursday","Friday"]
_TIME   = ["9am","10am","11am","2pm","3pm","4pm","5pm"]
_TOPIC  = ["API integration","product roadmap","Q3 planning","design review","sprint goals",
           "security audit","infrastructure upgrade","budget review","go-to-market strategy",
           "incident retrospective","release planning","hiring strategy"]
_ALERT_NOUNS = ["outage","latency spike","memory spike","disk usage alert","deploy failure"]

_SUS_SERVICES = ["CloudVault","DataSync","AccountHub","PaymentGateway","BillingPortal",
                 "StorageCloud","BackupNow","SecureVault","DocuPortal","InvoiceCenter",
                 "SubscriptionPro","NotifyHub","SyncDrive","AlertCenter","ServiceDesk"]
_SUS_TLDS     = ["com","net","io","org","co","biz","info"]
_SUS_ROLES    = ["support","noreply","billing","alerts","verify","admin","service","notify"]
_SUS_ACTIONS  = ["verify","confirm","review","update","validate","complete","activate"]

_BRANDS = {
    "paypal":    (["paypa1","paypai","pay-pal","paypa-l","p4ypal"],        "payment account"),
    "microsoft": (["micros0ft","m1crosoft","microsft","micro-soft","mlcrosoft"], "Microsoft 365 account"),
    "apple":     (["app1e","appl3","app-le","aapple","appie"],             "Apple ID"),
    "amazon":    (["amaz0n","amazn","amason","amazoon","am4zon"],          "Amazon account"),
    "netflix":   (["netfl1x","netlfix","netffix","netf1ix","nettflix"],    "Netflix subscription"),
    "google":    (["go0gle","g00gle","gooogle","goog1e","googie"],         "Google account"),
    "docusign":  (["docu-sign","d0cusign","docusiqn","docusgin"],         "DocuSign document"),
    "dropbox":   (["dr0pbox","dropb0x","dropbx","d-ropbox"],             "Dropbox account"),
}
_PHISH_TACTICS = ["typosquat","bec","credential","irs","it_helpdesk","payroll"]


# ── Clean generator ───────────────────────────────────────────────────────────

def gen_clean(rng: random.Random) -> dict:
    tactic = rng.choice(["meeting","update","alert","hr","infra"])

    if tactic == "meeting":
        name    = rng.choice(_FIRST)
        co      = rng.choice(_CO) + " " + rng.choice(_CO_SFX)
        topic   = rng.choice(_TOPIC)
        day     = rng.choice(_DAY)
        t       = rng.choice(_TIME)
        domain  = co.split()[0].lower() + ".com"
        return dict(
            mail_from=f"{name.lower()}@{domain}",
            subject=f"{topic.title()} — {day} {t}",
            body=(f"Hi,\n\nJust confirming our {topic} session on {day} at {t}.\n\n"
                  f"Please come prepared with your latest updates. We'll use the usual link.\n\n"
                  f"Thanks,\n{name}\n{rng.choice(_DEPT)}, {co}"),
            label=f"Meeting invite from {co}",
        )

    if tactic == "update":
        name    = rng.choice(_FIRST)
        dept    = rng.choice(_DEPT)
        version = f"v{rng.randint(1,5)}.{rng.randint(0,9)}.{rng.randint(0,9)}"
        feature = rng.choice(["authentication","dashboard","reporting","API","notifications","search"])
        return dict(
            mail_from=f"{dept.lower()}@mycompany.com",
            subject=f"Release {version} shipped — {feature} improvements",
            body=(f"Hi team,\n\nRelease {version} is now live.\n\n"
                  f"Key changes:\n- Improved {feature} performance\n"
                  f"- Bug fixes from last sprint\n- Updated documentation\n\n"
                  f"Rollback window closes in 2 hours. Ping {name} with any issues.\n\n{dept} Team"),
            label=f"Deployment notice {version}",
        )

    if tactic == "alert":
        svc   = rng.choice(["Datadog","PagerDuty","Grafana","Prometheus","CloudWatch"])
        noun  = rng.choice(_ALERT_NOUNS)
        env   = rng.choice(["prod","staging","dev-us","eu-west"])
        pct   = rng.randint(70, 95)
        return dict(
            mail_from=f"alerts@{svc.lower()}.com",
            subject=f"[RESOLVED] {noun} on {env}",
            body=(f"Alert resolved.\n\nService: {env}\nIssue: {noun}\n"
                  f"Peak usage: {pct}%\nDuration: {rng.randint(3,45)} minutes\n\n"
                  f"No action required. This alert has auto-resolved.\n\n— {svc}"),
            label=f"Resolved {svc} alert",
        )

    if tactic == "hr":
        event   = rng.choice(["team lunch","quarterly all-hands","office social","training day","hackathon"])
        day     = rng.choice(_DAY)
        venue   = rng.choice(["Level 2 boardroom","main cafeteria","rooftop terrace","Conference Room A","Building B"])
        return dict(
            mail_from="hr@mycompany.com",
            subject=f"Invitation: {event.title()} — {day}",
            body=(f"Hi team,\n\nYou're invited to our upcoming {event} on {day}.\n\n"
                  f"Venue: {venue}\nTime: {rng.choice(_TIME)}\n\n"
                  f"Please RSVP by {rng.choice(['Wednesday','Thursday','end of week'])}.\n\nHR Team"),
            label=f"HR {event} invitation",
        )

    # infra
    tool = rng.choice(["GitHub","Jira","Confluence","Slack","Datadog","AWS"])
    change = rng.choice(["scheduled maintenance","certificate renewal","API version upgrade","region migration"])
    window = f"{rng.randint(1,4)}:00–{rng.randint(5,8)}:00 UTC"
    return dict(
        mail_from=f"infra@mycompany.com",
        subject=f"[Notice] {tool} {change} — {rng.choice(_DAY)}",
        body=(f"Hi,\n\nWe will be performing a {change} for {tool}.\n\n"
              f"Maintenance window: {window}\nExpected downtime: {rng.randint(5,30)} minutes\n\n"
              f"No action required on your end.\n\nInfrastructure Team"),
        label=f"{tool} maintenance notice",
    )


# ── Suspicious generator ──────────────────────────────────────────────────────

def gen_suspicious(rng: random.Random) -> dict:
    svc    = rng.choice(_SUS_SERVICES)
    year   = rng.randint(2024, 2027)
    num    = rng.randint(1, 99)
    tld    = rng.choice(_SUS_TLDS)
    domain = f"{svc.lower()}-{year}.{tld}"
    role   = rng.choice(_SUS_ROLES)
    days   = rng.randint(3, 14)
    amount = rng.choice([49.99, 79.00, 149.99, 199.00, 249.99, 9.99, 29.99])
    action = rng.choice(_SUS_ACTIONS)
    gb     = rng.randint(1, 50)
    tactic = rng.choice(["account","backup","billing","subscription","it","survey","reward"])

    if tactic == "account":
        return dict(
            mail_from=f"{role}@{domain}",
            subject=f"Your account requires {action}ion",
            body=(f"Hi,\n\nWe noticed your account has not been {action}ed yet. "
                  f"To ensure continued access to our services please {action} within {days} days.\n\n"
                  f"This will only take a few minutes. Failure to {action} may result in "
                  f"restricted access.\n\n{svc} Account Team"),
            label=f"Account {action} — {domain}",
        )
    if tactic == "backup":
        return dict(
            mail_from=f"{role}@{domain}",
            subject=f"Your {gb}GB backup completed successfully",
            body=(f"Hello,\n\nYour scheduled backup completed successfully.\n\n"
                  f"{gb} GB of data has been secured on our servers.\n"
                  f"Next backup: {rng.choice(['tomorrow','in 3 days','next week'])}\n\n"
                  f"If you did not set up this service please contact us immediately.\n\n{svc} Support"),
            label=f"Backup notification — {domain}",
        )
    if tactic == "billing":
        return dict(
            mail_from=f"{role}@{domain}",
            subject=f"Invoice #{rng.randint(10000,99999)} pending your review",
            body=(f"Dear Customer,\n\nAn invoice of ${amount:.2f} is pending your review.\n\n"
                  f"Amount will be processed automatically in {days} days unless disputed.\n"
                  f"Please log in to {action} the invoice details.\n\n{svc} Finance Department"),
            label=f"Billing notice — {domain}",
        )
    if tactic == "subscription":
        return dict(
            mail_from=f"{role}@{domain}",
            subject=f"Your {svc} subscription renews in {days} days — ${amount:.2f}",
            body=(f"Hi,\n\nYour {svc} annual subscription is set to auto-renew in {days} days.\n\n"
                  f"Renewal amount: ${amount:.2f}\n\n"
                  f"Log in to {action} or cancel before renewal date.\n\n{svc} Billing"),
            label=f"Subscription renewal — {domain}",
        )
    if tactic == "it":
        return dict(
            mail_from=f"{role}@{domain}",
            subject=f"IT Notice: your password expires in {days} days",
            body=(f"Hi,\n\nYour company password will expire in {days} days.\n\n"
                  f"Please {action} your credentials soon to avoid being locked out.\n"
                  f"Contact {svc} helpdesk if you need assistance.\n\n{svc} IT Support"),
            label=f"IT password notice — {domain}",
        )
    if tactic == "survey":
        mins = rng.choice([2, 3, 5])
        return dict(
            mail_from=f"{role}@{domain}",
            subject=f"Quick {mins}-minute survey — your feedback matters",
            body=(f"Dear Customer,\n\nWe value your opinion. Please take {mins} minutes to "
                  f"{action} our satisfaction survey.\n\n"
                  f"Your responses help us improve our service.\n\n{svc} Customer Success"),
            label=f"Survey — {domain}",
        )
    # reward
    pts = rng.randint(500, 9999)
    return dict(
        mail_from=f"{role}@{domain}",
        subject=f"You have {pts:,} unclaimed reward points expiring soon",
        body=(f"Hi,\n\nYou have {pts:,} loyalty points that expire this month.\n\n"
              f"Log in to {action} them for gift cards or cashback before they expire.\n\n"
              f"{svc} Loyalty Rewards"),
        label=f"Reward points — {domain}",
    )


# ── Phishing generator ────────────────────────────────────────────────────────

def gen_phishing(rng: random.Random) -> dict:
    tactic = rng.choice(_PHISH_TACTICS)

    if tactic == "typosquat":
        brand, (typos, acct_name) = rng.choice(list(_BRANDS.items()))
        typo_base = rng.choice(typos)
        tld       = rng.choice(["com","net","org","io","co"])
        ext_tld   = rng.choice(["verify","secure","alert","account","login","update"])
        domain    = f"{typo_base}-{ext_tld}.{tld}"
        hours     = rng.choice([12, 24, 48, 72])
        action    = rng.choice(["verify","confirm","restore","secure","reactivate"])
        reason    = rng.choice(["unusual activity","a suspicious login","a policy update","your payment failing","a security review"])
        url_path  = rng.choice(["verify","restore","secure","confirm","unlock"])
        uid       = rng.randint(10000, 99999)
        return dict(
            mail_from=f"security@{domain}",
            subject=f"URGENT: Your {acct_name} has been {'suspended' if rng.random()>0.5 else 'limited'}",
            body=(f"Dear Customer,\n\nWe detected {reason} on your {acct_name}.\n\n"
                  f"Please {action} your identity immediately:\n"
                  f"http://{domain}/{url_path}?id={uid}\n\n"
                  f"You have {hours} hours or your account will be permanently closed.\n\n"
                  f"{brand.title()} Security Team"),
            label=f"{brand.title()} typosquat — {domain}",
        )

    if tactic == "bec":
        amount   = rng.choice([12500, 47500, 87000, 135000, 250000, 33750, 19999])
        bank     = rng.choice(["First National Trust","Pacific Commerce Bank","Meridian Financial","Atlantic Reserve","Global Trust Bank"])
        acct     = rng.randint(1000000000, 9999999999)
        routing  = rng.choice([21000021, 11000138, 21001088, 22300173, 9000782])
        deadline = rng.choice(["today","before 3pm","within the hour","before close of business"])
        exec_name= rng.choice(["CEO","CFO","COO","Chairman","Managing Director"])
        reason   = rng.choice(["closing an acquisition","settling a board-approved transaction",
                               "completing a time-sensitive deal","processing an urgent vendor payment"])
        return dict(
            mail_from=f"{exec_name.lower().replace(' ','-')}@{rng.choice(['company-exec-wire','corp-finance-urgent','board-transfer-secure'])}.{rng.choice(['net','com','org'])}",
            subject=f"CONFIDENTIAL: Urgent wire transfer — {exec_name} approval",
            body=(f"This is strictly confidential.\n\nWe are {reason} {deadline}. "
                  f"Wire ${amount:,} immediately to:\n\n"
                  f"Bank: {bank}\nAccount: {acct}\nRouting: {routing}\n\n"
                  f"Do NOT discuss this with anyone. Confirm by reply when done.\n\n{exec_name}"),
            label=f"BEC wire fraud — ${amount:,}",
        )

    if tactic == "credential":
        brand    = rng.choice(["IT Security","HR Department","Systems Administration","Corporate Security"])
        reason   = rng.choice(["a mandatory password reset","an urgent security audit","new compliance requirements","suspicious access detected"])
        hours    = rng.choice([4, 8, 12, 24])
        portal   = f"corp-{rng.choice(['security','helpdesk','it','hr','sso'])}-{rng.choice(['portal','login','access'])}.{rng.choice(['com','net','org'])}"
        uid      = rng.randint(10000, 99999)
        return dict(
            mail_from=f"noreply@{portal}",
            subject=f"Action Required: {reason.title()} within {hours} hours",
            body=(f"Dear Employee,\n\nDue to {reason}, you must update your credentials within {hours} hours.\n\n"
                  f"Failure to act will result in account lockout.\n\n"
                  f"Update now: http://{portal}/login?token={uid}\n\n"
                  f"Do not share this link. It is unique to your account.\n\n{brand}"),
            label=f"Credential harvest — {portal}",
        )

    if tactic == "irs":
        amount   = rng.choice([840, 1240, 2190, 3450, 780, 1890, 4200])
        year_ref = rng.choice([2023, 2024, 2025])
        domain   = f"irs-refund-{rng.randint(2024,2027)}.{rng.choice(['com','net','gov-refund.com'])}"
        uid      = rng.randint(100000, 999999)
        return dict(
            mail_from=f"refunds@{domain}",
            subject=f"IRS: Tax refund of ${amount:,} — claim within 72 hours",
            body=(f"Dear Taxpayer,\n\nAfter reviewing your {year_ref} tax return, "
                  f"the IRS has determined you are eligible for a refund of ${amount:,}.\n\n"
                  f"Claim your refund: http://{domain}/claim?ref={uid}\n\n"
                  f"This offer expires in 72 hours. Unclaimed refunds are forfeited.\n\nInternal Revenue Service"),
            label=f"IRS impersonation — ${amount:,} refund",
        )

    if tactic == "it_helpdesk":
        days   = rng.choice([1, 2, 3])
        domain = f"it-{rng.choice(['helpdesk','support','security','servicedesk'])}-{rng.randint(2024,2027)}.{rng.choice(['com','net','org'])}"
        uid    = rng.randint(10000, 99999)
        reason = rng.choice(["inactivity","a policy change","failed login attempts","an expired certificate","a system upgrade"])
        return dict(
            mail_from=f"helpdesk@{domain}",
            subject=f"URGENT: Account deactivation in {days} day{'s' if days>1 else ''} — verify now",
            body=(f"Dear User,\n\nYour corporate account is scheduled for deactivation due to {reason}.\n\n"
                  f"To keep your account active:\nhttp://{domain}/verify?user={uid}\n\n"
                  f"You have {days * 24} hours to respond before permanent deactivation.\n\nIT Security Department"),
            label=f"IT helpdesk impersonation — {domain}",
        )

    # payroll
    amount  = rng.choice([3200, 4800, 5500, 7200, 9100, 6300])
    domain  = f"payroll-{rng.choice(['secure','update','portal','hr'])}-{rng.randint(2024,2027)}.{rng.choice(['com','net','org'])}"
    uid     = rng.randint(10000, 99999)
    day     = rng.choice(_DAY)
    return dict(
        mail_from=f"payroll@{domain}",
        subject=f"Payroll: Confirm your bank details by {day} to avoid delays",
        body=(f"Dear Employee,\n\nOur payroll system is being upgraded. "
              f"Please confirm your bank account details by {day} to ensure "
              f"your ${amount:,} salary payment is processed without delay.\n\n"
              f"Update here: http://{domain}/confirm?emp={uid}\n\n"
              f"HR & Payroll Department"),
        label=f"Payroll BEC — ${amount:,}",
    )


# ── Send helper ───────────────────────────────────────────────────────────────

def send(email: dict, colour: str) -> None:
    msg = MIMEMultipart("alternative")
    msg["From"]    = email["mail_from"]
    msg["To"]      = RECIPIENT
    msg["Subject"] = email["subject"]
    msg.attach(MIMEText(email["body"], "plain"))

    print(f"{colour}{BOLD}  From   : {email['mail_from']}{RESET}")
    print(f"{colour}{BOLD}  Subject: {email['subject']}{RESET}")
    try:
        with smtplib.SMTP(PHISHGUARD_HOST, PHISHGUARD_PORT, timeout=30) as s:
            s.ehlo()
            s.sendmail(email["mail_from"], [RECIPIENT], msg.as_bytes())
        print(f"  {colour}✓ Accepted — {email['label']}{RESET}\n")
    except Exception as e:
        print(f"  ✗ Error: {e}\n")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed",  type=int, default=None, help="Random seed for reproducible run")
    parser.add_argument("--count", type=int, default=3,    help="Emails per category (default 3)")
    args = parser.parse_args()

    rng      = random.Random(args.seed)
    n        = max(1, args.count)
    seed_str = f"seed={args.seed}" if args.seed is not None else "random"

    print(f"\n{BOLD}{CYAN}PhishGuard SMTP Gateway — Procedural Demo ({seed_str}){RESET}")
    print(f"{CYAN}Generating {n} clean + {n} suspicious + {n} phishing to port {PHISHGUARD_PORT}{RESET}\n")
    print("─" * 60)

    cleans     = [gen_clean(rng)     for _ in range(n)]
    suspicious = [gen_suspicious(rng) for _ in range(n)]
    phishings  = [gen_phishing(rng)  for _ in range(n)]

    for i, e in enumerate(cleans, 1):
        print(f"\n{GREEN}{BOLD}[{i}/{n*3}] CLEAN{RESET}")
        send(e, GREEN)
        time.sleep(2)

    for i, e in enumerate(suspicious, 1):
        print(f"\n{YELLOW}{BOLD}[{n+i}/{n*3}] SUSPICIOUS{RESET}")
        send(e, YELLOW)
        time.sleep(2)

    for i, e in enumerate(phishings, 1):
        print(f"\n{RED}{BOLD}[{n*2+i}/{n*3}] PHISHING{RESET}")
        send(e, RED)
        time.sleep(2)

    print("─" * 60)
    print(f"\n{BOLD}All {n*3} sent. Expected results:{RESET}")
    print(f"  {GREEN}✅ {n} CLEAN      → Gmail inbox (label: PhishGuard-Delivered){RESET}")
    print(f"  {YELLOW}🟡 {n} SUSPICIOUS → Pending Review tab (press F5 first){RESET}")
    print(f"  {RED}🔴 {n} PHISHING   → Quarantine tab{RESET}")
    print(f"\n  {CYAN}Dashboard: http://localhost:8000{RESET}\n")


if __name__ == "__main__":
    main()
