"""Automatic weekly PDF report generation and email delivery."""

from __future__ import annotations

import datetime
import threading
import time
from pathlib import Path

import os

from database import db, DB_LOCK
from report_pdf import fetch_service_report_stats, build_report_pdf
from report_settings import get_weekly_settings, report_config, parse_recipient_emails
from techlog import get_logger

log = get_logger("weekly")

_TEST_SEND_LOCK = threading.Lock()
_RECENT_TEST_SENDS: dict[str, float] = {}
_TEST_DEDUP_SECONDS = 90

DATA_DIR = Path(os.environ.get("DATA_DIR", "data"))
LAST_RUN_FILE = DATA_DIR / "weekly_report_last.txt"
DEFAULT_PDF = DATA_DIR / "weekly_uptime.pdf"


def generate_report_for_range(
    start_date: datetime.date,
    end_date: datetime.date,
    service_ids: list[int] | None = None,
    output_path: Path | None = None,
) -> tuple[Path, list[dict]]:
    start_dt = datetime.datetime.combine(start_date, datetime.time.min)
    end_dt = datetime.datetime.combine(end_date, datetime.time.max)
    from_ts = start_dt.timestamp()
    to_ts = end_dt.timestamp()

    if not service_ids:
        with DB_LOCK:
            c = db()
            rows = c.execute("SELECT id FROM services ORDER BY id").fetchall()
            c.close()
        service_ids = [int(r["id"]) for r in rows]

    stats_list = []
    for sid in service_ids:
        stats = fetch_service_report_stats(sid, from_ts, to_ts, db, DB_LOCK)
        if stats:
            stats_list.append(stats)

    if not stats_list:
        raise ValueError("no services with data for report")

    out = output_path or DEFAULT_PDF
    out.parent.mkdir(parents=True, exist_ok=True)
    build_report_pdf(stats_list, start_date, end_date, out)
    return out, stats_list


def generate_last_n_days_report(
    days: int = 7,
    service_ids: list[int] | None = None,
) -> tuple[Path, datetime.date, datetime.date, list[dict]]:
    end_date = datetime.date.today()
    start_date = end_date - datetime.timedelta(days=days)
    pdf_path, stats = generate_report_for_range(start_date, end_date, service_ids=service_ids)
    return pdf_path, start_date, end_date, stats


def _already_ran_today() -> bool:
    if not LAST_RUN_FILE.exists():
        return False
    try:
        return LAST_RUN_FILE.read_text(encoding="utf-8").strip() == datetime.date.today().isoformat()
    except OSError:
        return False


def _mark_ran_today() -> None:
    LAST_RUN_FILE.parent.mkdir(parents=True, exist_ok=True)
    LAST_RUN_FILE.write_text(datetime.date.today().isoformat(), encoding="utf-8")


def run_weekly_report_job() -> None:
    enabled, to_addrs, _, _, days, service_ids = report_config()
    if not enabled:
        return
    if not to_addrs:
        raise ValueError("recipient emails are not configured in Settings → Reports")

    send_weekly_report_email(to_addrs, days, service_ids)


def _test_send_key(to_emails: str | list[str], days: int, service_ids: list[int] | None) -> str:
    ids = sorted(int(x) for x in (service_ids or []))
    emails = ",".join(parse_recipient_emails(to_emails))
    return f"{emails}|{days}|{','.join(str(x) for x in ids)}"


def acquire_test_send_slot(to_emails: str | list[str], days: int, service_ids: list[int] | None) -> bool:
    """Return False if an identical test email was sent recently (duplicate request)."""
    key = _test_send_key(to_emails, days, service_ids)
    now = time.time()
    with _TEST_SEND_LOCK:
        last = _RECENT_TEST_SENDS.get(key)
        if last is not None and now - last < _TEST_DEDUP_SECONDS:
            return False
        _RECENT_TEST_SENDS[key] = now
        return True


def release_test_send_slot(to_emails: str | list[str], days: int, service_ids: list[int] | None) -> None:
    key = _test_send_key(to_emails, days, service_ids)
    with _TEST_SEND_LOCK:
        _RECENT_TEST_SENDS.pop(key, None)


def send_weekly_report_email(
    to_emails: str | list[str],
    days: int = 7,
    service_ids: list[int] | None = None,
    *,
    test: bool = False,
) -> dict:
    recipients = parse_recipient_emails(to_emails)
    if not recipients:
        raise ValueError("recipient email is required")

    from mail_send import send_email, weekly_report_subject

    ids = service_ids or None
    pdf_path, start_date, end_date, stats = generate_last_n_days_report(days, service_ids=ids)
    subject = weekly_report_subject(end_date)
    if test:
        subject = f"[TEST] {subject}"
    send_email(recipients, subject, str(pdf_path))
    recipient_label = ", ".join(recipients)
    log.info(
        "Weekly report %semail sent to %s (%s services, %s to %s)",
        "test " if test else "",
        recipient_label, len(stats), start_date, end_date,
    )
    return {
        "to_emails": recipients,
        "services": len(stats),
        "start_date": str(start_date),
        "end_date": str(end_date),
        "pdf_path": str(pdf_path),
    }


def run_weekly_report_if_due() -> None:
    enabled, to_addrs, hour, weekday, _, _ = report_config()
    if not enabled or not to_addrs:
        return

    now = datetime.datetime.now()
    if now.weekday() != weekday or now.hour < hour:
        return
    if _already_ran_today():
        return

    try:
        run_weekly_report_job()
        _mark_ran_today()
    except Exception:
        log.exception("Scheduled weekly report failed")


_scheduler_started = False


def start_weekly_report_scheduler() -> None:
    global _scheduler_started
    if _scheduler_started:
        return
    _scheduler_started = True

    def _loop():
        while True:
            try:
                run_weekly_report_if_due()
            except Exception as e:
                log.error("Weekly report scheduler check failed: %s", e)
            time.sleep(300)

    threading.Thread(target=_loop, daemon=True, name="weekly-report").start()

    s = get_weekly_settings()
    weekdays = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
    if s["auto_enabled"] and s["to_emails"]:
        log.info(
            "Weekly report scheduler active — %s at %02d:00, last %s days → %s",
            weekdays[s["weekday"]] if 0 <= s["weekday"] <= 6 else "Fri",
            s["hour"],
            s["days"],
            ", ".join(s["to_emails"]),
        )
    else:
        log.info("Weekly report scheduler running — enable in Settings → Reports to send email")
