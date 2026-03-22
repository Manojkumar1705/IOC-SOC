"""
=============================================================
  Automated IOC Aggregation Tool
  Version  : 2.1
  Author   : SOC Automation Team
  Purpose  : Weekly IOC feed aggregation for SOC ingestion
             into Sumo Logic Threat Intelligence
  Output   : Single dated CSV — ioc_feeds_YYYY-MM-DD.csv
  Format   : Sumo Logic CSV (no header, 10 columns)
             id, indicator, type, source, validFrom,
             validUntil, confidence, threatType, actors,
             killChain
  Dedup    : IOC value only, persisted across weekly runs
             via ioc_dedup_state.json
  Config   : All API keys loaded from .env file
  Run      : python3 ioc_aggregator.py
=============================================================
"""

import os
import re
import csv
import json
import uuid
import time
import logging
import requests
import ipaddress
from datetime import datetime, timezone, timedelta
from collections import Counter
from pathlib import Path
from dotenv import load_dotenv

# ── Load environment variables from .env ─────────────────────────────────────
load_dotenv()

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("ioc_aggregator")

# ── Config ────────────────────────────────────────────────────────────────────
RUN_DATE         = datetime.now(timezone.utc).strftime("%Y-%m-%d")
OUTPUT_DIR       = Path(os.getenv("OUTPUT_DIR", "output"))
STATE_DIR        = Path(os.getenv("STATE_DIR", "state"))
OUTPUT_FILE      = OUTPUT_DIR / f"ioc_feeds_{RUN_DATE}.csv"
DEDUP_STATE_FILE = STATE_DIR / "ioc_dedup_state.json"
REQUEST_TIMEOUT  = int(os.getenv("REQUEST_TIMEOUT", "30"))

# ── API Keys (loaded from .env) ───────────────────────────────────────────────
API_KEYS = {
    "OTX":            os.getenv("OTX_API_KEY", ""),
    "MALSHARE":       os.getenv("MALSHARE_API_KEY", ""),
    "PULSEDIVE":      os.getenv("PULSEDIVE_API_KEY", ""),
    "ABUSECH":        os.getenv("ABUSECH_API_KEY", ""),
    "VIRUSTOTAL":     os.getenv("VIRUSTOTAL_API_KEY", ""),
    "ABUSEIPDB":      os.getenv("ABUSEIPDB_API_KEY", ""),
    "HYBRIDANALYSIS": os.getenv("HYBRIDANALYSIS_API_KEY", ""),
}

# ── Per-source confidence scores (STIX 2.1, 1-100) ───────────────────────────
SOURCE_CONFIDENCE = {
    "OTX": 60, "AbuseSSL": 85, "Firehol": 80, "EmergingThreats": 85,
    "Malshare": 80, "URLhaus": 85, "OpenPhish": 80, "PhishTank": 90,
    "Spamhaus": 90, "Feodo": 90, "BlocklistDE": 70, "Botvrij": 75,
    "VXVault": 75, "ThreatFox": 85, "Threatview": 80, "Pulsedive": 70,
    "VirusTotal": 90, "AbuseIPDB": 80, "MalwareBazaar": 88, "IPsum": 82,
    "CINSArmy": 78, "BambenekC2": 87, "BinaryDefense": 80, "TorExitNodes": 95,
    "DisconnectMe": 78, "DigitalSide": 82, "HybridAnalysis": 88,
}

# ── Kill chain mapper ─────────────────────────────────────────────────────────
KILLCHAIN_MAP = {
    "botnet_c2": "command-and-control", "cobalt_strike_c2": "command-and-control",
    "c2": "command-and-control", "malware": "installation",
    "malware_download": "delivery", "phishing": "delivery", "spam": "delivery",
    "bruteforce": "exploitation", "scanner": "reconnaissance",
    "blocklist": "reconnaissance", "compromised": "exploitation",
    "tor": "reconnaissance", "ransomware": "actions-on-objectives",
}

def get_kill_chain(raw):
    if not raw: return ""
    lower = raw.strip().lower()
    for key, phase in KILLCHAIN_MAP.items():
        if key in lower: return phase
    return ""

# ── Threat type normalizer ────────────────────────────────────────────────────
VALID_THREAT_TYPES = {
    "anomalous-activity", "anonymization", "benign",
    "compromised", "malicious-activity", "attribution", "unknown"
}
THREAT_MAP = {
    "malicious": "malicious-activity", "malware": "malicious-activity",
    "malware_download": "malicious-activity", "botnet_c2": "malicious-activity",
    "c2": "malicious-activity", "cobalt_strike_c2": "malicious-activity",
    "ransomware": "malicious-activity", "compromised": "compromised",
    "phishing": "anomalous-activity", "spam": "anomalous-activity",
    "bruteforce": "anomalous-activity", "scanner": "anomalous-activity",
    "tor": "anonymization", "vpn": "anonymization", "proxy": "anonymization",
    "high": "malicious-activity", "critical": "malicious-activity",
}

def normalize_threat(raw):
    if not raw: return "unknown"
    lower = raw.strip().lower()
    if lower in VALID_THREAT_TYPES: return lower
    if lower in THREAT_MAP: return THREAT_MAP[lower]
    for k, v in THREAT_MAP.items():
        if k in lower: return v
    return "malicious-activity"

# ── Helpers ───────────────────────────────────────────────────────────────────
def utc_now(): return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
def valid_until(ts):
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    return (dt + timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
def make_id(): return f"indicator--{uuid.uuid4()}"

def safe_get(url, **kwargs):
    try:
        r = requests.get(url, timeout=REQUEST_TIMEOUT, **kwargs)
        r.raise_for_status()
        return r
    except requests.RequestException as exc:
        log.warning("GET %s failed: %s", url, exc)
        return None

def safe_post(url, **kwargs):
    try:
        r = requests.post(url, timeout=REQUEST_TIMEOUT, **kwargs)
        r.raise_for_status()
        return r
    except requests.RequestException as exc:
        log.warning("POST %s failed: %s", url, exc)
        return None

# ── Validators ────────────────────────────────────────────────────────────────
def get_ip_type(value):
    try:
        addr = ipaddress.ip_address(value.strip().split("/")[0])
        return "ipv4-addr" if addr.version == 4 else "ipv6-addr"
    except ValueError: return None

def is_valid_hash(v): return bool(re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", v.strip()))
def hash_type(v):
    l = len(v.strip())
    if l == 32: return "file:hashes.MD5"
    if l == 40: return "file:hashes.SHA-1"
    if l == 64: return "file:hashes.SHA-256"
    return "file"
def is_valid_url(v): return v.strip().startswith(("http://", "https://", "ftp://"))
def is_valid_domain(v): return bool(re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", v.strip()))

# ── IOC record builders ───────────────────────────────────────────────────────
def make_record(kind, indicator, ioc_type, source, ts, threat, actors="", kc=""):
    return {
        "kind": kind, "id": make_id(), "indicator": indicator.strip(),
        "type": ioc_type, "source": source, "validFrom": ts,
        "validUntil": valid_until(ts),
        "confidence": SOURCE_CONFIDENCE.get(source, 75),
        "threatType": normalize_threat(threat),
        "actors": actors, "killChain": kc or get_kill_chain(threat),
    }

def ip_record(v, src, ts, threat="malicious-activity", actors="", kc=""):
    t = get_ip_type(v)
    return make_record("ip", v, t, src, ts, threat, actors, kc) if t else None

def url_record(v, src, ts, threat="malicious-activity", actors="", kc=""):
    return make_record("url", v, "url", src, ts, threat, actors, kc) if is_valid_url(v) else None

def domain_record(v, src, ts, threat="malicious-activity", actors="", kc=""):
    return make_record("domain", v, "domain-name", src, ts, threat, actors, kc) if is_valid_domain(v) else None

def hash_record(v, src, ts, threat="malicious-activity", actors="", kc=""):
    return make_record("hash", v, hash_type(v), src, ts, threat, actors, kc) if is_valid_hash(v) else None

def ioc_key(rec): return rec["indicator"].lower()

# ── Deduplication ─────────────────────────────────────────────────────────────
def load_seen():
    if DEDUP_STATE_FILE.exists():
        try: return set(json.loads(DEDUP_STATE_FILE.read_text()).get("seen", []))
        except Exception: pass
    return set()

def save_seen(seen):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    DEDUP_STATE_FILE.write_text(json.dumps({"seen": list(seen)}, indent=2))

# ═════════════════════════════════════════════════════════════════════════════
#  SOURCE FETCHERS
# ═════════════════════════════════════════════════════════════════════════════

def fetch_otx():
    records, ts = [], utc_now()
    key = API_KEYS["OTX"]
    if not key: log.warning("OTX_API_KEY not set — skipping"); return records
    r = safe_get("https://otx.alienvault.com/api/v1/pulses/subscribed",
                 headers={"X-OTX-API-KEY": key}, params={"limit": 50})
    if not r: return records
    for pulse in r.json().get("results", []):
        actor = pulse.get("adversary", "")
        threat = pulse.get("name", "malicious-activity")
        for ioc in pulse.get("indicators", []):
            itype, val = ioc.get("type", ""), ioc.get("indicator", "").strip()
            if not val: continue
            if itype in ("IPv4", "IPv6"):   rec = ip_record(val, "OTX", ts, threat, actor)
            elif itype == "URL":            rec = url_record(val, "OTX", ts, threat, actor)
            elif itype == "domain":         rec = domain_record(val, "OTX", ts, threat, actor)
            elif "FileHash" in itype:       rec = hash_record(val, "OTX", ts, threat, actor)
            else:                           rec = None
            if rec: records.append(rec)
    log.info("OTX → %d IOCs", len(records)); return records

def fetch_abuse_ssl():
    records, ts = [], utc_now()
    r = safe_get("https://sslbl.abuse.ch/blacklist/sslipblacklist.json")
    if not r: return records
    try:
        for e in r.json().get("results", []):
            rec = ip_record(e.get("DstIP", "").strip(), "AbuseSSL", ts, "botnet_c2")
            if rec: records.append(rec)
    except Exception as exc: log.error("AbuseSSL: %s", exc)
    log.info("AbuseSSL → %d IOCs", len(records)); return records

def fetch_firehol():
    records, ts = [], utc_now()
    r = safe_get("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset")
    if not r: return records
    for line in r.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        rec = ip_record(line, "Firehol", ts, "blocklist")
        if rec: records.append(rec)
    log.info("Firehol → %d IOCs", len(records)); return records

def fetch_emerging_threats():
    records, ts = [], utc_now()
    r = safe_get("https://rules.emergingthreats.net/blockrules/compromised-ips.txt")
    if not r: return records
    for line in r.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        rec = ip_record(line, "EmergingThreats", ts, "compromised")
        if rec: records.append(rec)
    log.info("EmergingThreats → %d IOCs", len(records)); return records

def fetch_malshare():
    records, ts = [], utc_now()
    key = API_KEYS["MALSHARE"]
    if not key: log.warning("MALSHARE_API_KEY not set — skipping"); return records
    r = safe_get(f"https://malshare.com/api.php?api_key={key}&action=getlistraw")
    if not r: return records
    for line in r.text.splitlines():
        rec = hash_record(line.strip(), "Malshare", ts, "malware")
        if rec: records.append(rec)
    log.info("Malshare → %d IOCs", len(records)); return records

def fetch_urlhaus():
    records, ts = [], utc_now()
    r = safe_get("https://urlhaus.abuse.ch/downloads/csv_recent/")
    if not r: return records
    for line in r.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        parts = [p.strip().strip('"') for p in line.split(",")]
        if len(parts) >= 6:
            rec = url_record(parts[2], "URLhaus", ts, parts[5] or "malicious-activity")
            if rec: records.append(rec)
    log.info("URLhaus → %d IOCs", len(records)); return records

def fetch_openphish():
    records, ts = [], utc_now()
    r = safe_get("https://openphish.com/feed.txt")
    if not r: return records
    for line in r.text.splitlines():
        rec = url_record(line.strip(), "OpenPhish", ts, "phishing")
        if rec: records.append(rec)
    log.info("OpenPhish → %d IOCs", len(records)); return records

def fetch_phishtank():
    records, ts = [], utc_now()
    r = safe_get("http://data.phishtank.com/data/online-valid.json")
    if not r: return records
    try:
        for e in r.json():
            rec = url_record(e.get("url", "").strip(), "PhishTank", ts, "phishing")
            if rec: records.append(rec)
    except Exception as exc: log.error("PhishTank: %s", exc)
    log.info("PhishTank → %d IOCs", len(records)); return records

def fetch_spamhaus():
    records, ts = [], utc_now()
    r = safe_get("https://www.spamhaus.org/drop/drop.txt")
    if not r: return records
    for line in r.text.splitlines():
        line = line.split(";")[0].strip()
        if not line or line.startswith(";"): continue
        rec = ip_record(line, "Spamhaus", ts, "spam")
        if rec: records.append(rec)
    log.info("Spamhaus → %d IOCs", len(records)); return records

def fetch_feodo():
    records, ts = [], utc_now()
    r = safe_get("https://feodotracker.abuse.ch/downloads/ipblocklist.json")
    if not r: return records
    try:
        for e in r.json():
            rec = ip_record(e.get("ip_address", "").strip(), "Feodo", ts, e.get("malware", "botnet_c2"))
            if rec: records.append(rec)
    except Exception as exc: log.error("Feodo: %s", exc)
    log.info("Feodo → %d IOCs", len(records)); return records

def fetch_blocklist_de():
    records, ts = [], utc_now()
    r = safe_get("https://lists.blocklist.de/lists/all.txt")
    if not r: return records
    for line in r.text.splitlines():
        rec = ip_record(line.strip(), "BlocklistDE", ts, "bruteforce")
        if rec: records.append(rec)
    log.info("BlocklistDE → %d IOCs", len(records)); return records

def fetch_botvrij():
    records, ts = [], utc_now()
    feeds = {
        "domain": ("https://www.botvrij.eu/data/ioclist.domain.raw", "malicious-activity"),
        "ip":     ("https://www.botvrij.eu/data/ioclist.ip-dst.raw",  "malicious-activity"),
        "url":    ("https://www.botvrij.eu/data/ioclist.url.raw",      "malicious-activity"),
        "hash":   ("https://www.botvrij.eu/data/ioclist.sha256.raw",   "malware"),
    }
    for kind, (url, threat) in feeds.items():
        r = safe_get(url)
        if not r: continue
        for line in r.text.splitlines():
            val = line.strip()
            if not val or val.startswith("#"): continue
            if kind == "ip":       rec = ip_record(val, "Botvrij", ts, threat)
            elif kind == "url":    rec = url_record(val, "Botvrij", ts, threat)
            elif kind == "domain": rec = domain_record(val, "Botvrij", ts, threat)
            else:                  rec = hash_record(val, "Botvrij", ts, threat)
            if rec: records.append(rec)
    log.info("Botvrij → %d IOCs", len(records)); return records

def fetch_vxvault():
    records, ts = [], utc_now()
    r = safe_get("http://vxvault.net/URL_List.php")
    if not r: return records
    for line in r.text.splitlines():
        rec = url_record(line.strip(), "VXVault", ts, "malware_download")
        if rec: records.append(rec)
    log.info("VXVault → %d IOCs", len(records)); return records

def fetch_threatfox():
    records, ts = [], utc_now()
    key = API_KEYS["ABUSECH"]
    if not key: log.warning("ABUSECH_API_KEY not set — skipping ThreatFox"); return records
    r = safe_post("https://threatfox-api.abuse.ch/api/v1/",
                  json={"query": "get_iocs", "days": 7},
                  headers={"Content-Type": "application/json", "Auth-Key": key})
    if not r: return records
    try:
        for e in r.json().get("data", []):
            itype  = e.get("ioc_type", "")
            val    = e.get("ioc", "").strip()
            threat = e.get("malware", "") or e.get("threat_type", "malicious-activity")
            if not val: continue
            if itype == "ip:port":                                   rec = ip_record(val.split(":")[0], "ThreatFox", ts, threat)
            elif itype == "url":                                     rec = url_record(val, "ThreatFox", ts, threat)
            elif itype == "domain":                                  rec = domain_record(val, "ThreatFox", ts, threat)
            elif itype in ("md5_hash", "sha1_hash", "sha256_hash"): rec = hash_record(val, "ThreatFox", ts, threat)
            else:                                                    rec = None
            if rec: records.append(rec)
    except Exception as exc: log.error("ThreatFox: %s", exc)
    log.info("ThreatFox → %d IOCs", len(records)); return records

def fetch_threatview():
    records, ts = [], utc_now()
    for url in [
        "https://threatview.io/Downloads/High-Confidence-CobaltStrike-C2%20-Feeds.txt",
        "https://threatview.io/Downloads/IP-High-Confidence-Feed.txt",
        "https://threatview.io/Downloads/DOMAIN-High-Confidence-Feed.txt",
    ]:
        r = safe_get(url)
        if not r: continue
        for line in r.text.splitlines():
            val = line.strip()
            if not val or val.startswith("#") or val.startswith(";"): continue
            if get_ip_type(val):       rec = ip_record(val, "Threatview", ts, "cobalt_strike_c2")
            elif is_valid_domain(val): rec = domain_record(val, "Threatview", ts, "cobalt_strike_c2")
            else:                      rec = None
            if rec: records.append(rec)
    log.info("Threatview → %d IOCs", len(records)); return records

def fetch_pulsedive():
    records, ts = [], utc_now()
    key = API_KEYS["PULSEDIVE"]
    if not key: log.warning("PULSEDIVE_API_KEY not set — skipping"); return records
    time.sleep(10)
    r = safe_get("https://pulsedive.com/api/explore.php",
                 params={"q": "risk=high,critical", "limit": 500, "pretty": 0, "key": key})
    if not r: return records
    try:
        for e in r.json().get("results", []):
            val, itype, threat = e.get("indicator","").strip(), e.get("type",""), e.get("risk","malicious-activity")
            if not val: continue
            if itype == "ip":       rec = ip_record(val, "Pulsedive", ts, threat)
            elif itype == "url":    rec = url_record(val, "Pulsedive", ts, threat)
            elif itype == "domain": rec = domain_record(val, "Pulsedive", ts, threat)
            elif itype == "hash":   rec = hash_record(val, "Pulsedive", ts, threat)
            else:                   rec = None
            if rec: records.append(rec)
    except Exception as exc: log.error("Pulsedive: %s", exc)
    log.info("Pulsedive → %d IOCs", len(records)); return records

def fetch_virustotal():
    records, ts = [], utc_now()
    key = API_KEYS["VIRUSTOTAL"]
    if not key: log.warning("VIRUSTOTAL_API_KEY not set — skipping"); return records
    headers = {"x-apikey": key}
    endpoints = [
        ("https://www.virustotal.com/api/v3/intelligence/search", {"query": "positives:5+ type:file ls:1d",   "limit": 40}, "hash"),
        ("https://www.virustotal.com/api/v3/intelligence/search", {"query": "positives:5+ type:url ls:1d",    "limit": 40}, "url"),
        ("https://www.virustotal.com/api/v3/intelligence/search", {"query": "positives:3+ type:domain ls:1d", "limit": 40}, "domain"),
    ]
    for endpoint, params, kind in endpoints:
        r = safe_get(endpoint, headers=headers, params=params)
        if not r: continue
        try:
            for e in r.json().get("data", []):
                attrs  = e.get("attributes", {})
                threat = attrs.get("popular_threat_classification", {}).get("suggested_threat_label", "malicious-activity")
                if kind == "hash":    val, rec = attrs.get("sha256",""), hash_record(attrs.get("sha256",""), "VirusTotal", ts, threat)
                elif kind == "url":   val, rec = attrs.get("url","") or e.get("id",""), url_record(attrs.get("url","") or e.get("id",""), "VirusTotal", ts, threat)
                elif kind == "domain":val, rec = e.get("id",""), domain_record(e.get("id",""), "VirusTotal", ts, threat)
                else:                 rec = None
                if rec: records.append(rec)
        except Exception as exc: log.error("VirusTotal %s: %s", kind, exc)
        time.sleep(15)
    log.info("VirusTotal → %d IOCs", len(records)); return records

def fetch_abuseipdb():
    records, ts = [], utc_now()
    key = API_KEYS["ABUSEIPDB"]
    if not key: log.warning("ABUSEIPDB_API_KEY not set — skipping"); return records
    r = safe_get("https://api.abuseipdb.com/api/v2/blacklist",
                 headers={"Key": key, "Accept": "application/json"},
                 params={"confidenceMinimum": 90, "limit": 10000})
    if not r: return records
    try:
        for e in r.json().get("data", []):
            score  = e.get("abuseConfidenceScore", 0)
            threat = "malicious-activity" if score >= 95 else "anomalous-activity"
            rec = ip_record(e.get("ipAddress","").strip(), "AbuseIPDB", ts, threat)
            if rec: records.append(rec)
    except Exception as exc: log.error("AbuseIPDB: %s", exc)
    log.info("AbuseIPDB → %d IOCs", len(records)); return records

def fetch_malwarebazaar():
    records, ts = [], utc_now()
    key = API_KEYS["ABUSECH"]
    if not key: log.warning("ABUSECH_API_KEY not set — skipping MalwareBazaar"); return records
    r = safe_post("https://mb-api.abuse.ch/api/v1/",
                  data={"query": "get_recent", "selector": "time"},
                  headers={"Auth-Key": key})
    if not r: return records
    try:
        for e in r.json().get("data", []):
            tags   = e.get("tags") or []
            threat = e.get("signature", "") or (tags[0] if tags else "malware")
            rec = hash_record(e.get("sha256_hash","").strip(), "MalwareBazaar", ts, threat)
            if rec: records.append(rec)
    except Exception as exc: log.error("MalwareBazaar: %s", exc)
    log.info("MalwareBazaar → %d IOCs", len(records)); return records

def fetch_ipsum():
    records, ts = [], utc_now()
    r = safe_get("https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt")
    if not r: return records
    for line in r.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        rec = ip_record(line.split()[0], "IPsum", ts, "blocklist")
        if rec: records.append(rec)
    log.info("IPsum → %d IOCs", len(records)); return records

def fetch_cins_army():
    records, ts = [], utc_now()
    r = safe_get("https://cinsscore.com/list/ci-badguys.txt")
    if not r: return records
    for line in r.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        rec = ip_record(line, "CINSArmy", ts, "scanner")
        if rec: records.append(rec)
    log.info("CINSArmy → %d IOCs", len(records)); return records

def fetch_bambenek_c2():
    records, ts = [], utc_now()
    r = safe_get("https://faf.bambenekconsulting.com/feeds/dga-feed.txt")
    if not r: return records
    for line in r.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        rec = domain_record(line.split(",")[0].strip(), "BambenekC2", ts, "botnet_c2")
        if rec: records.append(rec)
    log.info("BambenekC2 → %d IOCs", len(records)); return records

def fetch_binary_defense():
    records, ts = [], utc_now()
    r = safe_get("https://www.binarydefense.com/banlist.txt")
    if not r: return records
    for line in r.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        rec = ip_record(line, "BinaryDefense", ts, "malicious-activity")
        if rec: records.append(rec)
    log.info("BinaryDefense → %d IOCs", len(records)); return records

def fetch_tor_exit_nodes():
    records, ts = [], utc_now()
    r = safe_get("https://check.torproject.org/torbulkexitlist")
    if not r: return records
    for line in r.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        rec = ip_record(line, "TorExitNodes", ts, "tor")
        if rec: records.append(rec)
    log.info("TorExitNodes → %d IOCs", len(records)); return records

def fetch_disconnect_me():
    records, ts = [], utc_now()
    for url in [
        "https://s3.amazonaws.com/lists.disconnect.me/simple_malware.txt",
        "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
    ]:
        r = safe_get(url)
        if not r: continue
        for line in r.text.splitlines():
            line = line.strip().strip(".")
            if not line or line.startswith("#"): continue
            if is_valid_domain(line):
                rec = domain_record(line, "DisconnectMe", ts, "malware")
                if rec: records.append(rec)
    log.info("DisconnectMe → %d IOCs", len(records)); return records

def fetch_digitalside():
    records, ts = [], utc_now()
    feeds = {
        "ip":     "https://osint.digitalside.it/Threat-Intel/lists/latestips.txt",
        "domain": "https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt",
        "url":    "https://osint.digitalside.it/Threat-Intel/lists/latesturls.txt",
    }
    for kind, url in feeds.items():
        r = safe_get(url)
        if not r: continue
        for line in r.text.splitlines():
            val = line.strip()
            if not val or val.startswith("#"): continue
            if kind == "ip":       rec = ip_record(val, "DigitalSide", ts, "malicious-activity")
            elif kind == "domain": rec = domain_record(val, "DigitalSide", ts, "malicious-activity")
            elif kind == "url":    rec = url_record(val, "DigitalSide", ts, "malicious-activity")
            else:                  rec = None
            if rec: records.append(rec)
    log.info("DigitalSide → %d IOCs", len(records)); return records

def fetch_hybridanalysis():
    records, ts = [], utc_now()
    key = API_KEYS["HYBRIDANALYSIS"]
    if not key: log.warning("HYBRIDANALYSIS_API_KEY not set — skipping"); return records
    try:
        r = safe_post("https://www.hybrid-analysis.com/api/v2/feed/latest",
                      headers={"api-key": key, "User-Agent": "Falcon Sandbox",
                               "Content-Type": "application/x-www-form-urlencoded"},
                      data={"_fields": "sha256,threat_level,verdict,submit_name"})
        if not r: return records
        response = r.json()
        entries  = response if isinstance(response, list) else response.get("data", [])
        for e in entries:
            if isinstance(e, str):
                rec = hash_record(e.strip(), "HybridAnalysis", ts, "malware")
            elif isinstance(e, dict):
                sha256 = e.get("sha256", "").strip()
                threat = e.get("threat_level_human", e.get("verdict", "malware")) or "malware"
                rec    = hash_record(sha256, "HybridAnalysis", ts, threat) if sha256 else None
            else: rec = None
            if rec: records.append(rec)
    except Exception as exc: log.error("HybridAnalysis: %s", exc)
    log.info("HybridAnalysis → %d IOCs", len(records)); return records

# ── Fetcher registry ──────────────────────────────────────────────────────────
FETCHERS = [
    ("OTX",             fetch_otx),
    ("AbuseSSL",        fetch_abuse_ssl),
    ("Firehol",         fetch_firehol),
    ("EmergingThreats", fetch_emerging_threats),
    ("Malshare",        fetch_malshare),
    ("URLhaus",         fetch_urlhaus),
    ("OpenPhish",       fetch_openphish),
    ("PhishTank",       fetch_phishtank),
    ("Spamhaus",        fetch_spamhaus),
    ("Feodo",           fetch_feodo),
    ("BlocklistDE",     fetch_blocklist_de),
    ("Botvrij",         fetch_botvrij),
    ("VXVault",         fetch_vxvault),
    ("ThreatFox",       fetch_threatfox),
    ("Threatview",      fetch_threatview),
    ("Pulsedive",       fetch_pulsedive),
    ("VirusTotal",      fetch_virustotal),
    ("AbuseIPDB",       fetch_abuseipdb),
    ("MalwareBazaar",   fetch_malwarebazaar),
    ("IPsum",           fetch_ipsum),
    ("CINSArmy",        fetch_cins_army),
    ("BambenekC2",      fetch_bambenek_c2),
    ("BinaryDefense",   fetch_binary_defense),
    ("TorExitNodes",    fetch_tor_exit_nodes),
    ("DisconnectMe",    fetch_disconnect_me),
    ("DigitalSide",     fetch_digitalside),
    ("HybridAnalysis",  fetch_hybridanalysis),
]

# ── CSV row builder ───────────────────────────────────────────────────────────
def to_csv_row(rec):
    return [rec["id"], rec["indicator"], rec["type"], rec["source"],
            rec["validFrom"], rec["validUntil"], rec["confidence"],
            rec["threatType"], rec["actors"], rec["killChain"]]

# ── SOC summary ───────────────────────────────────────────────────────────────
def print_summary(src_counts, type_counts, total):
    log.info("")
    log.info("╔══════════════════════════════════════════════════╗")
    log.info("║         SOC FEED SUMMARY — %s           ║", RUN_DATE)
    log.info("╠══════════════════════════════════════════════════╣")
    log.info("║  Total new IOCs written : %-24d║", total)
    log.info("╠══════════════════════════════════════════════════╣")
    log.info("║  BY TYPE                                         ║")
    log.info("║  %-12s : %-32d║", "IPs",     type_counts.get("ip", 0))
    log.info("║  %-12s : %-32d║", "URLs",    type_counts.get("url", 0))
    log.info("║  %-12s : %-32d║", "Domains", type_counts.get("domain", 0))
    log.info("║  %-12s : %-32d║", "Hashes",  type_counts.get("hash", 0))
    log.info("╠══════════════════════════════════════════════════╣")
    log.info("║  BY SOURCE                                       ║")
    for src, cnt in sorted(src_counts.items(), key=lambda x: -x[1]):
        log.info("║  %-16s : %-28d║", src, cnt)
    log.info("╠══════════════════════════════════════════════════╣")
    log.info("║  Output : %-39s║", str(OUTPUT_FILE))
    log.info("╚══════════════════════════════════════════════════╝")

# ── Main pipeline ─────────────────────────────────────────────────────────────
def run():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    STATE_DIR.mkdir(parents=True, exist_ok=True)

    log.info("═══════════════════════════════════════════════════")
    log.info("  IOC Aggregation started  —  %s", utc_now())
    log.info("  Output : %s", OUTPUT_FILE)
    log.info("═══════════════════════════════════════════════════")

    seen = load_seen()
    log.info("Loaded %d previously seen IOC values", len(seen))

    all_records, src_counts = [], {}
    for name, fetcher in FETCHERS:
        try:
            fetched = fetcher()
            all_records.extend(fetched)
            src_counts[name] = len(fetched)
        except Exception as exc:
            log.error("Error in %s: %s", name, exc)
            src_counts[name] = 0

    log.info("Total raw IOCs: %d", len(all_records))

    new_records, this_run_seen = [], set()
    for rec in all_records:
        key = ioc_key(rec)
        if not key or key in seen or key in this_run_seen: continue
        this_run_seen.add(key)
        new_records.append(rec)

    log.info("New unique IOCs after dedup: %d", len(new_records))

    ORDER = {"ip": 0, "url": 1, "domain": 2, "hash": 3}
    new_records.sort(key=lambda r: ORDER[r["kind"]])
    type_counts = Counter(r["kind"] for r in new_records)

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerows(to_csv_row(r) for r in new_records)

    seen.update(this_run_seen)
    save_seen(seen)
    log.info("Dedup state saved (%d total known IOCs)", len(seen))

    deduped_src = Counter(r["source"] for r in new_records)
    print_summary(dict(deduped_src), dict(type_counts), len(new_records))


if __name__ == "__main__":
    run()
