# 🆘 HELP — Installation, Setup & Automation Guide

Complete guide to installing, configuring, running, and automating the **IOC Aggregation System** on both **Linux** and **Windows**.

---

## 📋 Table of Contents

1. [Requirements](#1-requirements)
2. [Installation](#2-installation)
3. [Configuration — API Keys](#3-configuration--api-keys)
4. [Running the Script](#4-running-the-script)
5. [Automating — Linux (Cron Job)](#5-automating--linux-cron-job)
6. [Automating — Windows (Task Scheduler)](#6-automating--windows-task-scheduler)
7. [Automating — APScheduler (Cross-platform)](#7-automating--apscheduler-cross-platform)
8. [Output Files](#8-output-files)
9. [Troubleshooting](#9-troubleshooting)

---

## 1. Requirements

| Requirement | Version |
|---|---|
| Python | 3.9 or higher |
| pip | Latest |
| Internet connection | Required (outbound HTTPS) |
| Operating System | Linux, macOS, or Windows |

---

## 2. Installation

### Step 1 — Clone the Repository

```bash
git clone https://github.com/Manojkumar1705/IOC-SOC.git
cd IOC-SOC
```

### Step 2 — Install Dependencies

**Linux / macOS:**
```bash
pip install -r requirements.txt
```

**Kali Linux (if you get "externally managed" error):**
```bash
pip install -r requirements.txt --break-system-packages
```

**Windows:**
```cmd
pip install -r requirements.txt
```

### Step 3 — Create Directories

The script creates these automatically on first run, but you can create them manually:

```bash
mkdir output state logs
```

---

## 3. Configuration — API Keys

### Step 1 — Copy the example file

**Linux / macOS:**
```bash
cp .env.example .env
```

**Windows:**
```cmd
copy .env.example .env
```

### Step 2 — Edit `.env` with your API keys

**Linux / macOS:**
```bash
nano .env
```

**Windows:**
```cmd
notepad .env
```

Fill in your keys:

```env
OTX_API_KEY=your_actual_key_here
MALSHARE_API_KEY=your_actual_key_here
PULSEDIVE_API_KEY=your_actual_key_here
ABUSECH_API_KEY=your_actual_key_here
VIRUSTOTAL_API_KEY=your_actual_key_here
ABUSEIPDB_API_KEY=your_actual_key_here
HYBRIDANALYSIS_API_KEY=your_actual_key_here
```

> ⚠️ **Never commit `.env` to GitHub.** It is already listed in `.gitignore`.

### Where to Get API Keys

| Source | Registration URL |
|---|---|
| OTX AlienVault | https://otx.alienvault.com |
| Malshare | https://malshare.com |
| Pulsedive | https://pulsedive.com |
| Abuse.ch (ThreatFox + MalwareBazaar) | https://auth.abuse.ch |
| VirusTotal | https://www.virustotal.com |
| AbuseIPDB | https://www.abuseipdb.com |
| HybridAnalysis | https://www.hybrid-analysis.com |

> All registrations are **free**. The 19 public feed sources require no API key at all.

---

## 4. Running the Script

**Linux / macOS / Kali:**
```bash
python3 ioc_aggregator.py
```

**Windows:**
```cmd
python ioc_aggregator.py
```

### What Happens During a Run

1. Loads API keys from `.env`
2. Loads previously seen IOCs from `state/ioc_dedup_state.json`
3. Fetches IOCs from all 27 sources (takes ~3–8 minutes)
4. Validates and normalizes each IOC
5. Deduplicates against previous weeks
6. Sorts into blocks: IPs → URLs → Domains → Hashes
7. Writes output to `output/ioc_feeds_YYYY-MM-DD.csv`
8. Saves updated dedup state
9. Prints the SOC summary to terminal

### Expected Terminal Output

```
2026-03-17T00:00:01Z  INFO   IOC Aggregation started
2026-03-17T00:00:02Z  INFO   Firehol → 4567 IOCs
2026-03-17T00:00:05Z  INFO   URLhaus → 19204 IOCs
2026-03-17T00:00:10Z  INFO   ThreatFox → 4620 IOCs
...
╔══════════════════════════════════════════════════╗
║         SOC FEED SUMMARY — 2026-03-17            ║
║  Total new IOCs written : 730508                 ║
║  IPs     : 57287                                 ║
║  URLs    : 76414                                 ║
║  Domains : 601200                                ║
║  Hashes  : 366                                   ║
╚══════════════════════════════════════════════════╝
```

---

## 5. Automating — Linux (Cron Job)

Cron runs directly on Linux/macOS without any extra installation.

### Step 1 — Find your Python path

```bash
which python3
# Example output: /usr/bin/python3
```

### Step 2 — Find your project path

```bash
pwd
# Example output: /home/pilot/IOC-SOC
```

### Step 3 — Open crontab

```bash
crontab -e
```

### Step 4 — Add this line at the bottom

```cron
# IOC Aggregator — Every Monday at 00:00 UTC
0 0 * * 1 cd /home/pilot/IOC-SOC && /usr/bin/python3 ioc_aggregator.py >> /home/pilot/IOC-SOC/logs/cron_$(date +\%Y-\%m-\%d).log 2>&1
```

> Replace `/home/pilot/IOC-SOC` with your actual project path.
> Replace `/usr/bin/python3` with your actual Python path from Step 1.

### Step 5 — Save and verify

```bash
# Save in nano: Ctrl+O → Enter → Ctrl+X
# Verify the cron is saved:
crontab -l
```

### Cron Schedule Reference

| Field | Value | Meaning |
|---|---|---|
| `0` | Minute | At minute 0 |
| `0` | Hour | At hour 0 (midnight) |
| `*` | Day of month | Every day |
| `*` | Month | Every month |
| `1` | Day of week | Monday (0=Sun, 1=Mon) |

---

## 6. Automating — Windows (Task Scheduler)

### Option A — Using the Batch Script (Easiest)

Create a file called `run_ioc.bat` in your project folder:

```bat
@echo off
cd /d C:\Users\YourName\IOC-SOC
python ioc_aggregator.py >> logs\run_%date:~10,4%-%date:~4,2%-%date:~7,2%.log 2>&1
```

> Replace `C:\Users\YourName\IOC-SOC` with your actual project path.

Then schedule it:

1. Open **Task Scheduler** (search in Start Menu)
2. Click **Create Basic Task**
3. Name it: `IOC Aggregator Weekly`
4. Trigger: **Weekly** → Monday → 12:00 AM
5. Action: **Start a program**
6. Program: browse to your `run_ioc.bat` file
7. Click **Finish**

### Option B — PowerShell Script

Save as `schedule_ioc.ps1` and run it **once** as Administrator to register the task:

```powershell
# schedule_ioc.ps1
# Run once as Administrator to register the weekly task

$Action = New-ScheduledTaskAction `
    -Execute "python" `
    -Argument "ioc_aggregator.py" `
    -WorkingDirectory "C:\Users\YourName\IOC-SOC"

$Trigger = New-ScheduledTaskTrigger `
    -Weekly `
    -DaysOfWeek Monday `
    -At "12:00AM"

$Settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Hours 2) `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 30)

Register-ScheduledTask `
    -TaskName "IOC Aggregator Weekly" `
    -Action $Action `
    -Trigger $Trigger `
    -Settings $Settings `
    -Description "Weekly IOC feed aggregation for SOC threat intelligence"

Write-Host "Task registered successfully. Runs every Monday at 00:00."
```

Run it:
```powershell
# Open PowerShell as Administrator, then:
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
.\schedule_ioc.ps1
```

---

## 7. Automating — APScheduler (Cross-platform)

APScheduler works on **both Linux and Windows** without any OS-level configuration. It runs as a long-lived Python process.

### Step 1 — Install APScheduler

```bash
pip install apscheduler
```

### Step 2 — Run the scheduler

```bash
python3 scheduler.py
```

This starts a blocking process that runs forever and triggers `ioc_aggregator.py` every Monday at 00:00 UTC.

### Step 3 — Keep it running with a process manager

**Linux — using `nohup` (simplest):**
```bash
nohup python3 scheduler.py > logs/scheduler.log 2>&1 &
echo "Scheduler running in background. PID: $!"
```

**Linux — using `screen`:**
```bash
screen -S ioc_scheduler
python3 scheduler.py
# Detach: Ctrl+A then D
# Reattach: screen -r ioc_scheduler
```

**Linux — using systemd (most reliable for production):**

Create `/etc/systemd/system/ioc-soc.service`:

```ini
[Unit]
Description=IOC Aggregator Weekly Scheduler
After=network.target

[Service]
Type=simple
User=pilot
WorkingDirectory=/home/pilot/IOC-SOC
ExecStart=/usr/bin/python3 /home/pilot/IOC-SOC/scheduler.py
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable ioc-soc
sudo systemctl start ioc-soc
sudo systemctl status ioc-soc
```

**Windows — run at startup:**

Add a shortcut to `python scheduler.py` in:
```
C:\Users\YourName\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
```

---

## 8. Output Files

| File | Location | Description |
|---|---|---|
| `ioc_feeds_YYYY-MM-DD.csv` | `output/` | Weekly IOC feed — upload to Sumo Logic |
| `ioc_dedup_state.json` | `state/` | Deduplication memory — do NOT delete |
| `cron_YYYY-MM-DD.log` | `logs/` | Cron run logs (Linux) |

### Uploading to Sumo Logic

1. Go to **Data Management → Threat Intelligence**
2. Click **+ Add Indicators**
3. Select **CSV** format
4. Upload the `ioc_feeds_YYYY-MM-DD.csv` file
5. Click **Import**

---

## 9. Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: dotenv` | python-dotenv not installed | `pip install python-dotenv` |
| `externally-managed-environment` error | Kali/Debian Python restriction | Add `--break-system-packages` flag |
| Source returns 0 IOCs | Feed temporarily down | Normal — script continues, retry next week |
| `429 Too Many Requests` | Rate limited (Pulsedive) | Built-in 10s delay handles this |
| Sumo Logic rejects the file | File too large or format issue | Check column count, no header row, trailing commas on empty fields |
| Cron not running | Wrong Python path or working dir | Verify paths with `which python3` and `pwd` |
| `ioc_dedup_state.json` missing | First run or deleted | Normal — script creates it fresh |

### Check if a source is working

```bash
# Test one fetcher in isolation
python3 -c "from ioc_aggregator import fetch_feodo; r = fetch_feodo(); print(f'{len(r)} IOCs')"
```

### Reset deduplication (start fresh)

```bash
rm state/ioc_dedup_state.json
python3 ioc_aggregator.py
```
