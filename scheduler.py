"""
=============================================================
  IOC Aggregator — APScheduler Automation
  Runs ioc_aggregator.py every Monday at 00:00 UTC
  Works on both Windows and Linux
  Usage: python3 scheduler.py
=============================================================
"""

from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger
import subprocess
import sys
import logging
from datetime import datetime, timezone

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("ioc_scheduler")


def run_aggregator():
    log.info("═══════════════════════════════════════════════════")
    log.info("  Scheduled IOC run triggered — %s",
             datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    log.info("═══════════════════════════════════════════════════")
    try:
        result = subprocess.run(
            [sys.executable, "ioc_aggregator.py"],
            capture_output=False,
        )
        if result.returncode == 0:
            log.info("IOC Aggregator completed successfully")
        else:
            log.error("IOC Aggregator exited with code %d", result.returncode)
    except Exception as exc:
        log.error("Failed to run IOC Aggregator: %s", exc)


if __name__ == "__main__":
    scheduler = BlockingScheduler(timezone="UTC")

    # Every Monday at 00:00 UTC
    scheduler.add_job(
        run_aggregator,
        trigger=CronTrigger(day_of_week="mon", hour=0, minute=0, timezone="UTC"),
        id="ioc_weekly_run",
        name="Weekly IOC Aggregation",
        misfire_grace_time=3600,   # allow up to 1 hour late start
    )

    log.info("Scheduler started — IOC Aggregator will run every Monday at 00:00 UTC")
    log.info("Press Ctrl+C to stop")

    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        log.info("Scheduler stopped")
