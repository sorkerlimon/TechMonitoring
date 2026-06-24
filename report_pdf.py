"""PDF uptime report generation for Tech Monitoring."""

from __future__ import annotations

import datetime
from pathlib import Path

from fpdf import FPDF


def _date_slug(d: datetime.date) -> str:
    return f"{d.year}-{d.month}-{d.day}"


def report_filename(start_date: datetime.date, end_date: datetime.date) -> str:
    start = _date_slug(start_date)
    end = _date_slug(end_date)
    if start_date == end_date:
        return f"weekly_uptime_{start}.pdf"
    return f"weekly_uptime_{start}_to_{end}.pdf"


def _days_until(date_str) -> int | None:
    if not date_str:
        return None
    try:
        return (datetime.date.fromisoformat(str(date_str)[:10]) - datetime.date.today()).days
    except ValueError:
        return None


def _fmt_expiry(date_str) -> str:
    if not date_str:
        return "N/A"
    days = _days_until(date_str)
    label = str(date_str)[:10]
    if days is None:
        return label
    return f"{label} ({days} days)"


def _safe_text(value) -> str:
    text = str(value or "")
    return text.encode("latin-1", errors="replace").decode("latin-1")


def fetch_service_report_stats(sid: int, from_ts: float, to_ts: float, db_func, db_lock) -> dict | None:
    with db_lock:
        c = db_func()
        service = c.execute("SELECT id, name, url FROM services WHERE id=?", (sid,)).fetchone()
        if not service:
            c.close()
            return None

        all_time = c.execute(
            """SELECT COUNT(*) AS total, SUM(is_up) AS up_count,
                      AVG(CASE WHEN is_up=1 THEN response_ms END) AS avg_ms
               FROM checks WHERE service_id=?""",
            (sid,),
        ).fetchone()

        row = c.execute(
            """SELECT
                   COUNT(*) AS total_checks,
                   SUM(is_up) AS up_checks,
                   AVG(CASE WHEN is_up=1 THEN response_ms END) AS avg_up_ms,
                   MIN(response_ms) AS min_ms,
                   MAX(response_ms) AS max_ms,
                   SUM(CASE WHEN response_ms > 1000 THEN 1 ELSE 0 END) AS peaks_over_1000
               FROM checks
               WHERE service_id=? AND ts>=? AND ts<=?""",
            (sid, from_ts, to_ts),
        ).fetchone()
        cert = c.execute(
            "SELECT ssl_expiry, domain_expiry FROM cert_info WHERE service_id=?",
            (sid,),
        ).fetchone()
        c.close()

    total_all = int(all_time["total"] or 0)
    up_all = int(all_time["up_count"] or 0)
    overall_uptime = round((up_all / total_all) * 100, 2) if total_all else 100.0
    avg_all_ms = round(all_time["avg_ms"], 2) if all_time and all_time["avg_ms"] is not None else 0.0

    total = int(row["total_checks"] or 0)
    up = int(row["up_checks"] or 0)
    range_uptime = round((up / total) * 100, 2) if total else 100.0

    return {
        "id": service["id"],
        "name": service["name"],
        "url": service["url"],
        "overall_uptime_pct": overall_uptime,
        "avg_response_ms": avg_all_ms,
        "range_uptime_pct": range_uptime,
        "range_avg_response_ms": round(row["avg_up_ms"], 2) if row and row["avg_up_ms"] is not None else 0.0,
        "range_min_ms": round(row["min_ms"], 2) if row and row["min_ms"] is not None else 0.0,
        "range_max_ms": round(row["max_ms"], 2) if row and row["max_ms"] is not None else 0.0,
        "peaks_over_1000": int(row["peaks_over_1000"] or 0),
        "total_checks": total,
        "ssl_expiry": cert["ssl_expiry"] if cert else None,
        "domain_expiry": cert["domain_expiry"] if cert else None,
    }


def _fmt_date(d: datetime.date) -> str:
    return d.strftime("%d %b %Y")


class _ReportPDF(FPDF):
    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")


def build_report_pdf(
    services_stats: list[dict],
    start_date: datetime.date,
    end_date: datetime.date,
    output_path: str | Path,
) -> Path:
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    pdf = _ReportPDF()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=20)

    range_label = f"{_fmt_date(start_date)} - {_fmt_date(end_date)}"
    generated = datetime.datetime.now().strftime("%d %b %Y %H:%M")

    for idx, stats in enumerate(services_stats):
        pdf.add_page()
        pdf.set_text_color(30, 30, 30)

        pdf.set_font("Helvetica", "B", 18)
        pdf.cell(0, 10, "Tech Monitoring Report", ln=True)

        pdf.set_font("Helvetica", "", 11)
        pdf.set_text_color(80, 80, 80)
        pdf.cell(0, 7, f"Report period: {range_label}", ln=True)
        pdf.cell(0, 7, f"Generated: {generated}", ln=True)
        pdf.ln(6)

        pdf.set_draw_color(34, 197, 94)
        pdf.set_line_width(0.8)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(8)

        pdf.set_text_color(20, 20, 20)
        pdf.set_font("Helvetica", "B", 15)
        pdf.cell(0, 9, _safe_text(stats["name"]), ln=True)

        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(60, 60, 60)
        pdf.cell(0, 6, _safe_text(stats["url"]), ln=True)
        pdf.ln(4)

        rows = [
            ("Overall Uptime", f"{stats['range_uptime_pct']:.2f}%"),
            ("Avg Response Time", f"{stats['avg_response_ms']:.2f} ms"),
            ("Avg Response in Range", f"{stats['range_avg_response_ms']:.2f} ms"),
            ("Min Response (range)", f"{stats['range_min_ms']:.2f} ms"),
            ("Max Response (range)", f"{stats['range_max_ms']:.2f} ms"),
            ("No. of Peaks Above 1000 ms", str(stats["peaks_over_1000"])),
            ("Certificate Expiry", _fmt_expiry(stats.get("ssl_expiry"))),
            ("Domain Expiry", _fmt_expiry(stats.get("domain_expiry"))),
        ]

        col_w = (190 - 20) / 2
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_fill_color(245, 245, 245)
        pdf.cell(col_w, 8, "Metric", border=1, fill=True)
        pdf.cell(col_w, 8, "Value", border=1, fill=True, ln=True)

        pdf.set_font("Helvetica", "", 10)
        for i, (label, value) in enumerate(rows):
            fill = i % 2 == 0
            if fill:
                pdf.set_fill_color(252, 252, 252)
            pdf.cell(col_w, 8, label, border=1, fill=fill)
            pdf.cell(col_w, 8, value, border=1, fill=fill, ln=True)

        if idx < len(services_stats) - 1:
            pdf.ln(4)

    if not services_stats:
        pdf.add_page()
        pdf.set_font("Helvetica", "", 12)
        pdf.cell(0, 10, "No services selected for this report.", ln=True)

    pdf.output(str(out))
    return out
