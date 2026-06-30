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


def _fmt_duration(seconds: float) -> str:
    total = max(0, int(round(seconds)))
    if total == 0:
        return "0 sec"
    hours, rem = divmod(total, 3600)
    minutes, secs = divmod(rem, 60)
    parts = []
    if hours:
        parts.append(f"{hours} hr" if hours == 1 else f"{hours} hrs")
    if minutes:
        parts.append(f"{minutes} min")
    if secs or not parts:
        parts.append(f"{secs} sec")
    return " ".join(parts)


def _compute_downtime_stats(checks, from_ts: float, to_ts: float, pre_up=None) -> dict:
    incidents: list[float] = []
    down_start = None

    if pre_up is False:
        down_start = from_ts

    prev_up = pre_up
    for ch in checks:
        ts = float(ch["ts"])
        is_up = bool(ch["is_up"])
        if prev_up is None:
            if not is_up:
                down_start = ts
            prev_up = is_up
            continue
        if prev_up and not is_up:
            down_start = ts
        elif not prev_up and is_up and down_start is not None:
            incidents.append(max(0.0, ts - down_start))
            down_start = None
        prev_up = is_up

    if down_start is not None:
        incidents.append(max(0.0, to_ts - down_start))

    total = sum(incidents)
    count = len(incidents)
    avg = total / count if count else 0.0
    highest = max(incidents) if incidents else 0.0
    return {
        "total_seconds": total,
        "avg_seconds": avg,
        "highest_seconds": highest,
        "incident_count": count,
    }


def _safe_text(value) -> str:
    text = str(value or "")
    return text.encode("latin-1", errors="replace").decode("latin-1")


def fetch_service_report_stats(sid: int, from_ts: float, to_ts: float, db_func, db_lock) -> dict | None:
    with db_lock:
        c = db_func()
        service = c.execute("SELECT id, name, url, interval FROM services WHERE id=?", (sid,)).fetchone()
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
        check_rows = c.execute(
            """SELECT ts, is_up FROM checks
               WHERE service_id=? AND ts>=? AND ts<=?
               ORDER BY ts ASC""",
            (sid, from_ts, to_ts),
        ).fetchall()
        prev_check = c.execute(
            """SELECT is_up FROM checks
               WHERE service_id=? AND ts<?
               ORDER BY ts DESC LIMIT 1""",
            (sid, from_ts),
        ).fetchone()
        c.close()

    pre_up = None if not prev_check else bool(prev_check["is_up"])
    downtime = _compute_downtime_stats(check_rows, from_ts, to_ts, pre_up=pre_up)

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
        "total_downtime_seconds": downtime["total_seconds"],
        "avg_downtime_seconds": downtime["avg_seconds"],
        "highest_downtime_seconds": downtime["highest_seconds"],
        "downtime_incidents": downtime["incident_count"],
    }


def _fmt_date(d: datetime.date) -> str:
    return d.strftime("%d %b %Y")


# Premium palette
_NAVY = (15, 23, 42)
_NAVY_MID = (30, 41, 59)
_ACCENT = (37, 99, 235)
_SLATE = (100, 116, 139)
_MUTED = (148, 163, 184)
_LIGHT = (248, 250, 252)
_ROW_ALT = (241, 245, 249)
_BORDER = (226, 232, 240)
_WHITE = (255, 255, 255)
_TEXT = (30, 41, 59)
_SUCCESS = (22, 163, 74)
_WARN = (217, 119, 6)
_DANGER = (220, 38, 38)


def _service_health_status(stats: dict) -> tuple[str, tuple[int, int, int]]:
    uptime = stats["range_uptime_pct"]
    peaks = stats["peaks_over_1000"]
    downtime = stats.get("total_downtime_seconds", 0)
    if uptime < 95 or downtime > 3600:
        return "Critical", _DANGER
    if uptime < 99.9 or peaks > 0 or downtime > 0:
        return "Warning", _WARN
    return "Healthy", _SUCCESS


def _aggregate_cover_stats(services_stats: list[dict]) -> dict:
    n = len(services_stats)
    avg_uptime = round(sum(s["range_uptime_pct"] for s in services_stats) / n, 2) if n else 100.0
    total_downtime = sum(s.get("total_downtime_seconds", 0) for s in services_stats)
    total_peaks = sum(s["peaks_over_1000"] for s in services_stats)
    total_checks = sum(s.get("total_checks", 0) for s in services_stats)
    issues = sum(1 for s in services_stats if _service_health_status(s)[0] != "Healthy")
    expiring: list[tuple[str, str, str, int]] = []
    for s in services_stats:
        for key, label in (("ssl_expiry", "Certificate"), ("domain_expiry", "Domain")):
            days = _days_until(s.get(key))
            if days is not None and days <= 30:
                expiring.append((s["name"], label, str(s.get(key))[:10], days))
    return {
        "service_count": n,
        "avg_uptime": avg_uptime,
        "total_downtime": total_downtime,
        "total_peaks": total_peaks,
        "total_checks": total_checks,
        "issues": issues,
        "expiring": expiring,
    }


def _executive_summary_text(range_label: str, agg: dict) -> str:
    n = agg["service_count"]
    uptime = agg["avg_uptime"]
    parts = [
        f"All {n} service{'s' if n != 1 else ''} were monitored during {range_label}.",
        f"Average uptime was {uptime:.2f}%.",
    ]
    if agg["total_downtime"] > 0:
        parts.append(f"Total downtime across services was {_fmt_duration(agg['total_downtime'])}.")
    else:
        parts.append("No downtime was recorded in this period.")
    if agg["total_peaks"] > 0:
        parts.append(
            f"{agg['total_peaks']} slow response peak{'s' if agg['total_peaks'] != 1 else ''} "
            f"above 1000 ms were detected."
        )
    if agg["issues"]:
        parts.append(f"{agg['issues']} service{'s' if agg['issues'] != 1 else ''} need attention.")
    else:
        parts.append("All services are operating within healthy thresholds.")
    return " ".join(parts)


class _ReportPDF(FPDF):
    def __init__(self):
        super().__init__()
        self.set_margins(14, 14, 14)

    def footer(self):
        self.set_y(-14)
        self.set_draw_color(*_BORDER)
        self.line(14, self.get_y(), 196, self.get_y())
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*_MUTED)
        self.cell(95, 8, "Tech Monitoring  |  Confidential", align="L")
        self.cell(95, 8, f"Page {self.page_no()}/{{nb}}", align="R")

    def _draw_cover(self, range_label: str, generated: str, services_stats: list[dict]):
        self.add_page()
        agg = _aggregate_cover_stats(services_stats)
        table_x = 14
        table_w = 182

        self.set_fill_color(*_NAVY)
        self.rect(0, 0, 210, 58, style="F")
        self.set_fill_color(*_ACCENT)
        self.rect(0, 58, 210, 1.2, style="F")

        self.set_y(20)
        self.set_text_color(*_WHITE)
        self.set_font("Helvetica", "B", 24)
        self.cell(0, 11, "TECH MONITORING", align="C", new_x="LMARGIN", new_y="NEXT")
        self.set_font("Helvetica", "", 11)
        self.set_text_color(186, 198, 214)
        self.cell(0, 7, "Uptime & Performance Report", align="C", new_x="LMARGIN", new_y="NEXT")

        self._draw_cover_info_boxes(range_label, generated, agg)
        self._draw_cover_kpi_row(agg)
        self._draw_cover_summary(range_label, agg)
        self._draw_cover_overview_table(services_stats)
        if agg["expiring"]:
            self._draw_cover_expiring_alerts(agg["expiring"])

        self.ln(4)
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*_MUTED)
        self.cell(0, 4, "Detailed metrics for each service begin on the following pages.", align="C")

    def _draw_cover_info_boxes(self, range_label: str, generated: str, agg: dict):
        boxes = [
            ("Report Period", range_label),
            ("Generated", generated),
            ("Services", str(agg["service_count"])),
            ("Total Checks", str(agg["total_checks"])),
        ]
        gap = 4
        box_w = (182 - gap * (len(boxes) - 1)) / len(boxes)
        y = 68
        for i, (label, value) in enumerate(boxes):
            x = 14 + i * (box_w + gap)
            self.set_fill_color(*_LIGHT)
            self.set_draw_color(*_BORDER)
            self.rect(x, y, box_w, 20, style="FD")
            self.set_xy(x + 4, y + 3)
            self.set_font("Helvetica", "", 6)
            self.set_text_color(*_SLATE)
            self.cell(box_w - 8, 3, label.upper(), new_x="LMARGIN", new_y="NEXT")
            self.set_x(x + 4)
            self.set_font("Helvetica", "B", 9 if i < 2 else 11)
            self.set_text_color(*_NAVY)
            display = _safe_text(value)
            if len(display) > 22 and i < 2:
                self.set_font("Helvetica", "B", 8)
            self.cell(box_w - 8, 6, display, new_x="LMARGIN", new_y="NEXT")
        self.set_y(y + 26)

    def _draw_cover_kpi_row(self, agg: dict):
        uptime = agg["avg_uptime"]
        uptime_color = _SUCCESS if uptime >= 99.9 else (_WARN if uptime >= 95 else _DANGER)
        issues = agg["issues"]
        issues_color = _SUCCESS if issues == 0 else _WARN
        boxes = [
            ("Avg Uptime", f"{uptime:.2f}%", uptime_color),
            ("Need Attention", str(issues), issues_color),
            ("Total Downtime", _fmt_duration(agg["total_downtime"]), _NAVY),
            ("Peaks > 1000ms", str(agg["total_peaks"]), _NAVY),
        ]
        gap = 4
        w = (182 - gap * 3) / 4
        y = self.get_y() + 2
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*_ACCENT)
        self.cell(0, 5, "EXECUTIVE OVERVIEW", new_x="LMARGIN", new_y="NEXT")
        self.ln(2)
        y = self.get_y()
        for i, (label, value, color) in enumerate(boxes):
            x = 14 + i * (w + gap)
            self.set_fill_color(*_WHITE)
            self.set_draw_color(*_BORDER)
            self.rect(x, y, w, 22, style="FD")
            self.set_fill_color(*_ACCENT)
            self.rect(x, y, w, 1.2, style="F")
            self.set_xy(x + 3, y + 4)
            self.set_font("Helvetica", "", 6)
            self.set_text_color(*_SLATE)
            self.cell(w - 6, 3, label.upper(), new_x="LMARGIN", new_y="NEXT")
            self.set_xy(x + 3, y + 11)
            self.set_font("Helvetica", "B", 12)
            self.set_text_color(*color)
            self.cell(w - 6, 7, _safe_text(value), new_x="LMARGIN", new_y="NEXT")
        self.set_y(y + 28)

    def _draw_cover_summary(self, range_label: str, agg: dict):
        self.ln(2)
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*_ACCENT)
        self.cell(0, 5, "SUMMARY", new_x="LMARGIN", new_y="NEXT")
        self.ln(1)
        self.set_font("Helvetica", "", 9)
        self.set_text_color(*_TEXT)
        self.set_x(14)
        self.multi_cell(182, 4.5, _safe_text(_executive_summary_text(range_label, agg)))
        self.ln(3)

    def _draw_cover_overview_table(self, services_stats: list[dict]):
        table_x = 14
        table_w = 182
        pad = 5
        row_h = 8
        cols = (
            ("Service", 58),
            ("Uptime", 32),
            ("Avg Response", 42),
            ("Status", 30),
        )

        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*_ACCENT)
        self.cell(0, 5, "SERVICE HEALTH OVERVIEW", new_x="LMARGIN", new_y="NEXT")
        self.ln(2)

        header_y = self.get_y()
        y = header_y
        self.set_fill_color(*_NAVY_MID)
        self.rect(table_x, y, table_w, row_h, style="F")
        x = table_x + pad
        self.set_xy(x, y + 2)
        self.set_font("Helvetica", "B", 7)
        self.set_text_color(*_WHITE)
        for label, width in cols:
            self.cell(width, 4, label.upper())
        self.set_y(y + row_h)

        for i, stats in enumerate(services_stats):
            y = self.get_y()
            if i % 2 == 0:
                self.set_fill_color(*_ROW_ALT)
                self.rect(table_x, y, table_w, row_h, style="F")
            status, status_color = _service_health_status(stats)
            x = table_x + pad
            self.set_xy(x, y + 2)
            self.set_font("Helvetica", "B", 8)
            self.set_text_color(*_TEXT)
            name = _safe_text(stats["name"])
            if len(name) > 24:
                name = name[:23] + "..."
            self.cell(cols[0][1], 4, name)
            self.set_font("Helvetica", "", 8)
            uptime = stats["range_uptime_pct"]
            up_color = _SUCCESS if uptime >= 99.9 else (_WARN if uptime >= 95 else _DANGER)
            self.set_text_color(*up_color)
            self.cell(cols[1][1], 4, f"{uptime:.2f}%")
            self.set_text_color(*_TEXT)
            self.cell(cols[2][1], 4, f"{stats['range_avg_response_ms']:.0f} ms")
            self.set_font("Helvetica", "B", 8)
            self.set_text_color(*status_color)
            self.cell(cols[3][1], 4, status)
            self.set_y(y + row_h)

        self.set_draw_color(*_BORDER)
        self.rect(table_x, header_y, table_w, self.get_y() - header_y, style="D")
        self.ln(4)

    def _draw_cover_expiring_alerts(self, expiring: list[tuple[str, str, str, int]]):
        table_x = 14
        table_w = 182
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*_WARN)
        self.cell(0, 5, "EXPIRING SOON (WITHIN 30 DAYS)", new_x="LMARGIN", new_y="NEXT")
        self.ln(2)
        block_y = self.get_y()
        for i, (service, kind, date_str, days) in enumerate(expiring):
            y = self.get_y()
            if i % 2 == 0:
                self.set_fill_color(*_ROW_ALT)
                self.rect(table_x, y, table_w, 8, style="F")
            self.set_xy(table_x + 5, y + 2)
            self.set_font("Helvetica", "B", 8)
            self.set_text_color(*_TEXT)
            self.cell(45, 4, _safe_text(service))
            self.set_font("Helvetica", "", 8)
            self.set_text_color(*_SLATE)
            self.cell(50, 4, kind)
            self.set_text_color(*_WARN)
            self.cell(0, 4, f"{date_str} ({days} days)", new_x="LMARGIN", new_y="NEXT")
        block_h = self.get_y() - block_y
        if block_h > 0:
            self.set_draw_color(*_BORDER)
            self.rect(table_x, block_y, table_w, block_h, style="D")
        self.ln(3)

    def _draw_service_header(self, stats: dict):
        y = self.get_y()
        self.set_fill_color(*_NAVY_MID)
        self.rect(14, y, 182, 20, style="F")
        self.set_xy(18, y + 4)
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(*_WHITE)
        self.cell(0, 7, _safe_text(stats["name"]), new_x="LMARGIN", new_y="NEXT")
        self.set_xy(18, y + 12)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(186, 198, 214)
        self.cell(0, 5, _safe_text(stats["url"]), new_x="LMARGIN", new_y="NEXT")
        self.set_y(y + 26)

    def _draw_kpi_row(self, stats: dict):
        uptime = stats["range_uptime_pct"]
        uptime_color = _SUCCESS if uptime >= 99.9 else (_WARN if uptime >= 95 else (220, 38, 38))
        boxes = [
            ("Overall Uptime", f"{uptime:.2f}%", uptime_color),
            ("Avg Response", f"{stats['range_avg_response_ms']:.0f} ms", _NAVY),
            ("Peaks > 1000ms", str(stats["peaks_over_1000"]), _NAVY),
        ]
        w = 58
        gap = 4
        y = self.get_y()
        for i, (label, value, color) in enumerate(boxes):
            x = 14 + i * (w + gap)
            self.set_fill_color(*_WHITE)
            self.set_draw_color(*_BORDER)
            self.rect(x, y, w, 24, style="FD")
            self.set_fill_color(*_ACCENT)
            self.rect(x, y, w, 1.5, style="F")
            self.set_xy(x + 4, y + 5)
            self.set_font("Helvetica", "", 7)
            self.set_text_color(*_SLATE)
            self.cell(w - 8, 4, label.upper(), new_x="LMARGIN", new_y="NEXT")
            self.set_xy(x + 4, y + 12)
            self.set_font("Helvetica", "B", 14)
            self.set_text_color(*color)
            self.cell(w - 8, 8, value, new_x="LMARGIN", new_y="NEXT")
        self.set_y(y + 30)

    def _section_title(self, title: str):
        self.ln(2)
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*_ACCENT)
        self.cell(0, 5, title.upper(), new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*_BORDER)
        y = self.get_y()
        self.line(14, y, 196, y)
        self.ln(4)

    def _metric_row(self, label: str, value: str, alt: bool = False):
        table_x = 14
        table_w = 182
        pad = 5
        value_w = 58
        row_h = 9
        y = self.get_y()

        if alt:
            self.set_fill_color(*_ROW_ALT)
            self.rect(table_x, y, table_w, row_h, style="F")

        label_w = table_w - (pad * 2) - value_w
        x_label = table_x + pad
        x_value = table_x + table_w - pad - value_w

        self.set_xy(x_label, y + 2.5)
        self.set_font("Helvetica", "", 9)
        self.set_text_color(*_TEXT)
        self.cell(label_w, 5, label)

        self.set_xy(x_value, y + 2.5)
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*_NAVY_MID)
        self.cell(value_w, 5, _safe_text(value), align="R")

        self.set_y(y + row_h)

    def _draw_metrics_table(self, sections: list[tuple[str, list[tuple[str, str]]]]):
        table_x = 14
        table_w = 182
        row_idx = 0
        for section_title, rows in sections:
            self._section_title(section_title)
            block_y = self.get_y()
            for label, value in rows:
                self._metric_row(label, value, alt=row_idx % 2 == 0)
                row_idx += 1
            block_h = self.get_y() - block_y
            if block_h > 0:
                self.set_draw_color(*_BORDER)
                self.rect(table_x, block_y, table_w, block_h, style="D")
            self.ln(3)


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
    pdf.set_auto_page_break(auto=True, margin=18)

    range_label = f"{_fmt_date(start_date)} - {_fmt_date(end_date)}"
    generated = datetime.datetime.now().strftime("%d %b %Y  %H:%M")

    if not services_stats:
        pdf.add_page()
        pdf.set_font("Helvetica", "", 12)
        pdf.set_text_color(*_TEXT)
        pdf.cell(0, 10, "No services selected for this report.", new_x="LMARGIN", new_y="NEXT")
        pdf.output(str(out))
        return out

    pdf._draw_cover(range_label, generated, services_stats)

    for stats in services_stats:
        pdf.add_page()
        pdf._draw_service_header(stats)
        pdf._draw_kpi_row(stats)

        sections = [
            ("Availability", [
                ("Overall Uptime", f"{stats['range_uptime_pct']:.2f}%"),
                ("Total Downtime", _fmt_duration(stats.get("total_downtime_seconds", 0))),
                ("Avg Downtime", _fmt_duration(stats.get("avg_downtime_seconds", 0))),
                ("Highest Downtime", _fmt_duration(stats.get("highest_downtime_seconds", 0))),
            ]),
            ("Performance", [
                ("Avg Response Time (all time)", f"{stats['avg_response_ms']:.2f} ms"),
                ("Avg Response in Range", f"{stats['range_avg_response_ms']:.2f} ms"),
                ("Min Response (range)", f"{stats['range_min_ms']:.2f} ms"),
                ("Max Response (range)", f"{stats['range_max_ms']:.2f} ms"),
                ("No. of Peaks Above 1000 ms", str(stats["peaks_over_1000"])),
            ]),
            ("Certificate & Domain", [
                ("Certificate Expiry", _fmt_expiry(stats.get("ssl_expiry"))),
                ("Domain Expiry", _fmt_expiry(stats.get("domain_expiry"))),
            ]),
        ]
        pdf._draw_metrics_table(sections)

    pdf.output(str(out))
    return out
