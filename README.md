# 🛡️ Automated IOC Aggregation System

A Python-based automated threat intelligence pipeline that collects **Indicators of Compromise (IOCs)** from **27 open-source feeds and authenticated APIs**, normalizes them into a standardized format, deduplicates across sources and weekly runs, and produces a clean CSV file ready for direct ingestion into **Sumo Logic Threat Intelligence**.

---

## 📌 Why This Project Exists

Cybersecurity teams depend on IOCs to detect and respond to threats, yet open-source intelligence feeds are fragmented, inconsistent, and often redundant. Manually collecting and normalizing data from 27+ sources every week is time-consuming and error-prone.

This tool automates the entire pipeline — from fetching to normalization to deduplication to output — so SOC analysts receive a clean, enriched, deduplicated feed every Monday without any manual effort.

---

## 🧰 Language & Technologies

| Component | Technology |
|---|---|
| Language | Python 3.9+ |
| HTTP Requests | `requests` library |
| IP Validation | `ipaddress` (stdlib) |
| Credential Management | `.env` + `python-dotenv` |
| Scheduling (optional) | `APScheduler` |
| Output Format | CSV — Sumo Logic Threat Intel Ingest spec |
| Deduplication State | JSON file persistence |

---

## ⚙️ Methods Used

| Method | Description |
|---|---|
| **Regex-driven classification** | Validates and classifies each IOC as IP, URL, domain, or file hash using `re` and `ipaddress` |
| **Cross-source deduplication** | IOC values are hashed into a set and checked against a persistent weekly state file |
| **Confidence scoring** | Each source is assigned a 1–100 confidence score based on feed reputation per STIX 2.1 |
| **Kill chain mapping** | Raw threat labels are mapped to Lockheed Martin Cyber Kill Chain phases automatically |
| **Threat type normalization** | All source-specific labels are normalized to valid STIX 2.1 `threatType` values |
| **Graceful error handling** | Each fetcher is wrapped independently — one failing source never stops the full run |

---

## 📦 Python Modules Used

| Module | Purpose |
|---|---|
| `requests` | HTTP GET/POST to all 27 source feeds and APIs |
| `python-dotenv` | Loads API keys securely from `.env` file |
| `ipaddress` | Validates IPs and determines IPv4 vs IPv6 |
| `re` | Regex validation for hashes, domains, URLs |
| `csv` | Writes the final Sumo Logic CSV output |
| `json` | Reads/writes the deduplication state file |
| `uuid` | Generates unique `indicator--uuid4` IDs per row |
| `logging` | Structured timestamped terminal output |
| `datetime` | UTC timestamp generation and `validUntil` calculation |
| `collections.Counter` | SOC summary breakdown by source and type |
| `pathlib.Path` | Cross-platform file path management |
| `apscheduler` | Weekly scheduling (optional, in `scheduler.py`) |

---

## 🌐 Sources Used

### API Sources (require key)

| # | Source | IOC Types | Description | URL |
|---|---|---|---|---|
| 1 | **OTX AlienVault** | IP, URL, Domain, Hash | Community-driven threat intel with pulse-based IOC sharing and adversary attribution | https://otx.alienvault.com |
| 2 | **Malshare** | Hash | Malware repository providing daily hash feeds of newly discovered malware samples | https://malshare.com |
| 3 | **Pulsedive** | IP, URL, Domain, Hash | Threat intelligence aggregator providing risk-rated indicators with enrichment | https://pulsedive.com |
| 4 | **ThreatFox** | IP, URL, Domain, Hash | Abuse.ch IOC database with malware family tagging and structured threat data | https://threatfox.abuse.ch |
| 5 | **MalwareBazaar** | Hash | Abuse.ch malware sample database with hash feeds and malware family tags | https://bazaar.abuse.ch |
| 6 | **VirusTotal** | URL, Domain, Hash | Multi-engine file and URL analysis platform providing malware verdicts | https://www.virustotal.com |
| 7 | **AbuseIPDB** | IP | Crowdsourced IP abuse reports with confidence scoring based on report volume | https://www.abuseipdb.com |
| 8 | **HybridAnalysis** | Hash | Falcon Sandbox-verified malware hashes from dynamic analysis of submitted files | https://www.hybrid-analysis.com |

### Public Feed Sources (no key required)

| # | Source | IOC Types | Description | URL |
|---|---|---|---|---|
| 9 | **AbuseSSL** | IP | Abuse.ch SSL blacklist tracking botnet C2 servers using SSL certificates | https://sslbl.abuse.ch |
| 10 | **Firehol Level 1** | IP | Curated multi-source IP blocklist aggregating the most dangerous known bad IPs | https://github.com/firehol/blocklist-ipsets |
| 11 | **Emerging Threats** | IP | Industry-respected list of IPs involved in known compromised infrastructure | https://rules.emergingthreats.net |
| 12 | **URLhaus** | URL | Abuse.ch feed of actively malicious URLs used for malware distribution | https://urlhaus.abuse.ch |
| 13 | **OpenPhish** | URL | Verified phishing URLs identified through automated and manual analysis | https://openphish.com |
| 14 | **PhishTank** | URL | Community-verified phishing URLs with human review process | https://phishtank.org |
| 15 | **Spamhaus DROP** | IP | One of the most trusted global blocklists covering botnet-controlled IP ranges | https://www.spamhaus.org/drop |
| 16 | **Feodo Tracker** | IP | Abuse.ch tracker for banking malware C2 infrastructure (Emotet, Dridex, TrickBot) | https://feodotracker.abuse.ch |
| 17 | **Blocklist.de** | IP | High-volume IP feed of brute-force attack sources across SSH, mail, and web | https://lists.blocklist.de |
| 18 | **Botvrij** | IP, URL, Domain, Hash | Belgian CERT-provided IOC feed covering all indicator types | https://www.botvrij.eu |
| 19 | **VXVault** | URL | Malware payload URL list tracking active malware distribution infrastructure | http://vxvault.net |
| 20 | **Threatview** | IP, Domain | High-confidence Cobalt Strike C2 IP and domain feed for targeted SOC use | https://threatview.io |
| 21 | **IPsum** | IP | Aggregates 30+ IP blocklists into a single feed with occurrence-based scoring | https://github.com/stamparm/ipsum |
| 22 | **CINS Army** | IP | Daily updated feed of scanner and brute-force attack source IPs | https://cinsscore.com |
| 23 | **Bambenek C2** | Domain | Research-backed feed of DGA malware C2 domains | https://osint.bambenekconsulting.com/feeds |
| 24 | **Binary Defense** | IP | Actively maintained IP banlist from Binary Defense threat research team | https://www.binarydefense.com/banlist.txt |
| 25 | **Tor Exit Nodes** | IP | Official Tor Project list of active exit nodes — definitive anonymization feed | https://check.torproject.org/torbulkexitlist |
| 26 | **Disconnect.me** | Domain | Malware and tracking domain list maintained by the Disconnect privacy project | https://disconnect.me |
| 27 | **DigitalSide** | IP, URL, Domain | Italian CERT-aligned OSINT feed covering multiple indicator types | https://osint.digitalside.it |

---

## 📁 Project Structure

```
IOC-SOC/
├── ioc_aggregator.py      # Main aggregation script
├── scheduler.py           # APScheduler weekly automation
├── .env                   # Your API keys (never commit this)
├── .env.example           # Template — copy to .env and fill in keys
├── .gitignore             # Excludes .env, output/, state/ from git
├── requirements.txt       # Python dependencies
├── README.md              # Project overview (this file)
├── HELP.md                # Installation, setup, and automation guide
├── output/                # Generated CSV files (auto-created)
│   └── ioc_feeds_YYYY-MM-DD.csv
└── state/                 # Dedup persistence (auto-created)
    └── ioc_dedup_state.json
```

---

## 📤 Output Format

The output file follows the **Sumo Logic CSV upload specification** exactly. No header row. 10 columns per row:

```
id, indicator, type, source, validFrom, validUntil, confidence, threatType, actors, killChain
```

**Example rows:**
```
indicator--uuid, 1.2.3.4, ipv4-addr, Feodo, 2026-03-12T08:00:00Z, 2026-03-19T08:00:00Z, 90, malicious-activity,,command-and-control
indicator--uuid, http://evil.com, url, URLhaus, 2026-03-12T08:00:00Z, 2026-03-19T08:00:00Z, 85, malicious-activity,,delivery
indicator--uuid, malware.xyz, domain-name, BambenekC2, 2026-03-12T08:00:00Z, 2026-03-19T08:00:00Z, 87, malicious-activity,,command-and-control
indicator--uuid, d41d8cd98f00b204e9800998ecf8427e, file:hashes.MD5, MalwareBazaar, 2026-03-12T08:00:00Z, 2026-03-19T08:00:00Z, 88, malicious-activity,,installation
```

---

## 🚀 Quick Start

See **[HELP.md](HELP.md)** for full installation, setup, and automation instructions.

```bash
# 1. Clone the repo
git clone https://github.com/Manojkumar1705/IOC-Aggregator.git
cd IOC-SOC

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure API keys
cp .env.example .env
nano .env   # fill in your keys

# 4. Run
python3 ioc_aggregator.py
```

---

## 👥 Team

Developed by the SOC Automation Team — Hindustan Institute of Technology & Science

- Manoj Kumar R (23SU2400039)
- Gowshik S (23SU2400022)
- Sivamuthu Selvadurai M (23SU2400071)
