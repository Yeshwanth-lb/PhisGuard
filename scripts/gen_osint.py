import os, ast
dq = chr(34)
tq = dq * 3
ht = "https://"
sl = chr(47)

VT_IP   = ht + "www.virustotal.com/api/v3/ip_addresses/"
VT_URL  = ht + "www.virustotal.com/api/v3/urls/"
ABUSE   = ht + "api.abuseipdb.com/api/v2/check"
URLHAUS = ht + "urlhaus-api.abuse.ch/v1/url/"

p = os.path.join("app", "layer1", "osint_client.py")

file_lines = [
    tq + "Async OSINT lookups: VirusTotal, AbuseIPDB, URLhaus, Spamhaus, MISP." + tq + "\n",
    "import asyncio\n",
    "import socket\n",
    "import structlog\n",
    "import httpx\n",
    "from typing import Optional\n",
    "from app.layer1.cache import L1Cache\n",
    "\n",
    "logger = structlog.get_logger()\n",
    "\n",
]

file_lines += [
    "VT_IP_BASE   = " + dq + VT_IP   + dq + "\n",
    "VT_URL_BASE  = " + dq + VT_URL  + dq + "\n",
    "ABUSE_BASE   = " + dq + ABUSE   + dq + "\n",
    "URLHAUS_BASE = " + dq + URLHAUS + dq + "\n",
    "\n",
]

with open(p, "w") as f:
    pass
print("gen_osint placeholder written")
