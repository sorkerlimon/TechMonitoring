"""Notification channels and alert delivery for Tech Monitoring."""

import json
import os
import ssl
import threading
import datetime
import smtplib
import urllib.request
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from pathlib import Path

from flask import request, jsonify
from techlog import get_logger

log = get_logger("notify")

NOTIFY_TYPES = {"slack", "email"}
NOTIFY_EVENTS = {"down", "up", "cert_expiry", "domain_expiry"}
EXPIRY_THRESHOLDS = (30, 14, 7, 1, 0)

_db = None
_db_lock = None
_current_user = None
_service_state = {}
_expiry_sent = {}


def configure(db_func, db_lock, current_user_fn):
    global _db, _db_lock, _current_user
    _db = db_func
    _db_lock = db_lock
    _current_user = current_user_fn


def seed_service_state(service_id, is_up):
    _service_state[service_id] = bool(is_up)


def clear_service_state(service_id):
    _service_state.pop(service_id, None)
    for key in list(_expiry_sent):
        if key[0] == service_id:
            _expiry_sent.pop(key, None)


def _days_until(date_str):
    if not date_str:
        return None
    try:
        d = datetime.date.fromisoformat(str(date_str)[:10])
        return (d - datetime.date.today()).days
    except ValueError:
        return None


def check_expiry_alerts(service_id, name, url, ssl_expiry, domain_expiry):
    checks = (
        ("cert_expiry", ssl_expiry),
        ("domain_expiry", domain_expiry),
    )
    for event, date_str in checks:
        days = _days_until(date_str)
        if days is None:
            continue
        for threshold in EXPIRY_THRESHOLDS:
            if days > threshold:
                continue
            key = (service_id, event, threshold)
            if _expiry_sent.get(key):
                break
            _expiry_sent[key] = True
            log.info(
                "Expiry alert service_id=%s name=%s event=%s days=%s threshold=%s",
                service_id, name, event, days, threshold,
            )
            notify_monitor_event(service_id, event, name, url, {
                "expiry_date": str(date_str)[:10],
                "days_remaining": days,
                "threshold": threshold,
            })
            break


def handle_check_result(service_id, is_up, name, url, *, status_code=None, response_ms=0):
    is_up = bool(is_up)
    prev_up = _service_state.get(service_id)
    if prev_up is not None:
        prev_up = bool(prev_up)
        if prev_up != is_up:
            event = "up" if is_up else "down"
            log.info("Status change service_id=%s name=%s event=%s", service_id, name, event)
            notify_monitor_event(service_id, event, name, url, {
                "status_code": status_code,
                "response_ms": response_ms,
            })
    _service_state[service_id] = is_up


def parse_events(raw):
    if isinstance(raw, list):
        return [e for e in raw if e in NOTIFY_EVENTS]
    if isinstance(raw, str):
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                return [e for e in data if e in NOTIFY_EVENTS]
        except json.JSONDecodeError:
            pass
        return [e.strip() for e in raw.split(",") if e.strip() in NOTIFY_EVENTS]
    return []


def _mask_config(channel_type, config):
    masked = dict(config)
    if channel_type == "slack" and masked.get("webhook_url"):
        u = masked["webhook_url"]
        masked["webhook_url"] = u[:28] + "…" + u[-6:] if len(u) > 40 else "••••••••"
    if channel_type == "webhook" and masked.get("url"):
        u = masked["url"]
        masked["url"] = u[:28] + "…" + u[-6:] if len(u) > 40 else "••••••••"
    if channel_type == "email" and masked.get("smtp_pass"):
        masked["smtp_pass"] = "••••••••"
    return masked


def channel_row(row, mask=True):
    cfg = json.loads(row["config"]) if row["config"] else {}
    if mask:
        cfg = _mask_config(row["type"], cfg)
    return {
        "id": row["id"],
        "name": row["name"],
        "type": row["type"],
        "config": cfg,
        "events": parse_events(row["events"]),
        "enabled": bool(row["enabled"]),
        "created_at": row["created_at"],
    }


def list_channels(enabled_only=False):
    with _db_lock:
        c = _db()
        q = "SELECT * FROM notification_channels"
        if enabled_only:
            q += " WHERE enabled=1"
        q += " ORDER BY id"
        rows = c.execute(q).fetchall()
        c.close()
    return [dict(r) for r in rows]


def list_channel_options():
    return [
        {"id": ch["id"], "name": ch["name"], "type": ch["type"], "enabled": bool(ch["enabled"])}
        for ch in list_channels()
    ]


def get_service_channel_ids(service_id):
    with _db_lock:
        c = _db()
        rows = c.execute(
            """SELECT channel_id FROM service_notifications WHERE service_id=? ORDER BY channel_id""",
            (service_id,),
        ).fetchall()
        c.close()
    return [r["channel_id"] for r in rows]


def set_service_channels(service_id, channel_ids):
    ids = []
    for raw in channel_ids or []:
        try:
            ids.append(int(raw))
        except (TypeError, ValueError):
            pass
    with _db_lock:
        c = _db()
        c.execute("DELETE FROM service_notifications WHERE service_id=?", (service_id,))
        for cid in ids:
            ok = c.execute(
                "SELECT 1 FROM notification_channels WHERE id=? LIMIT 1",
                (cid,),
            ).fetchone()
            if ok:
                c.execute(
                    "INSERT OR IGNORE INTO service_notifications(service_id, channel_id) VALUES(?,?)",
                    (service_id, cid),
                )
        c.commit()
        c.close()


def get_channels_for_service(service_id):
    with _db_lock:
        c = _db()
        rows = c.execute(
            """SELECT nc.* FROM notification_channels nc
               INNER JOIN service_notifications sn ON sn.channel_id = nc.id
               WHERE sn.service_id=? AND nc.enabled=1
               ORDER BY nc.id""",
            (service_id,),
        ).fetchall()
        c.close()
    return [dict(r) for r in rows]


def _format_alert(event, service_name, service_url, extra=None):
    extra = extra or {}
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if event == "down":
        title = "Service DOWN"
        icon = "🔴"
        detail = f"Status: {extra.get('status_code') or 'N/A'} | Response: {extra.get('response_ms', 0):.0f}ms"
    elif event == "up":
        title = "Service RECOVERED"
        icon = "🟢"
        detail = f"Status: {extra.get('status_code') or 'OK'} | Response: {extra.get('response_ms', 0):.0f}ms"
    elif event == "cert_expiry":
        days = extra.get("days_remaining", 0)
        exp = extra.get("expiry_date", "unknown")
        if days <= 0:
            title = "Certificate EXPIRED"
            icon = "🔴"
        else:
            title = "Certificate expiring soon"
            icon = "🔒"
        detail = f"Expires: {exp} | {days} day{'s' if days != 1 else ''} remaining"
    elif event == "domain_expiry":
        days = extra.get("days_remaining", 0)
        exp = extra.get("expiry_date", "unknown")
        if days <= 0:
            title = "Domain EXPIRED"
            icon = "🔴"
        else:
            title = "Domain expiring soon"
            icon = "🌐"
        detail = f"Expires: {exp} | {days} day{'s' if days != 1 else ''} remaining"
    else:
        title = "Alert"
        icon = "ℹ️"
        detail = ""
    return (
        f"{icon} {title}\n"
        f"Name: {service_name}\n"
        f"URL: {service_url}\n"
        f"{detail}\n"
        f"Time: {ts}"
    )


def _send_slack(config, message):
    url = (config.get("webhook_url") or "").strip()
    if not url:
        raise ValueError("webhook_url required")
    payload = json.dumps({"text": message}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=15)


def _send_webhook(config, message, event, service_name, service_url, extra):
    url = (config.get("url") or "").strip()
    if not url:
        raise ValueError("url required")
    method = (config.get("method") or "POST").upper()
    body = json.dumps({
        "event": event,
        "message": message,
        "service": {"name": service_name, "url": service_url},
        "extra": extra,
        "timestamp": datetime.datetime.now().isoformat(),
    }).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method=method,
        headers={"Content-Type": "application/json", "User-Agent": "TechMonitoring/1.0"},
    )
    urllib.request.urlopen(req, timeout=15)


def _resolve_email_config(config, *, env_fallback=True):
    cfg = dict(config or {})
    if env_fallback:
        from_addr = (cfg.get("from") or os.environ.get("MAIL_FROM_ADDRESS") or cfg.get("smtp_user") or "").strip()
        from_name = (os.environ.get("MAIL_FROM_NAME") or "").strip().strip('"')
        host = (cfg.get("smtp_host") or os.environ.get("MAIL_HOST") or "").strip()
        port = int(cfg.get("smtp_port") or os.environ.get("MAIL_PORT") or 587)
        user = (cfg.get("smtp_user") or os.environ.get("MAIL_USERNAME") or "").strip()
        password = cfg.get("smtp_pass") or os.environ.get("MAIL_PASSWORD") or ""
    else:
        from_addr = (cfg.get("from") or cfg.get("smtp_user") or "").strip()
        from_name = ""
        host = (cfg.get("smtp_host") or "").strip()
        port = int(cfg.get("smtp_port") or 587)
        user = (cfg.get("smtp_user") or "").strip()
        password = cfg.get("smtp_pass") or ""
    return {
        "to": (cfg.get("to") or "").strip(),
        "from": from_addr,
        "from_header": f"{from_name} <{from_addr}>" if from_name and from_addr else from_addr,
        "host": host,
        "port": port,
        "user": user,
        "password": password,
        "use_tls": bool(cfg.get("use_tls", True)),
    }


def _pdf_attachment_part(pdf_path: str) -> MIMEApplication:
    path = Path(pdf_path)
    if not path.exists():
        raise FileNotFoundError(f"PDF not found: {pdf_path}")
    with open(path, "rb") as f:
        part = MIMEApplication(f.read(), _subtype="pdf")
    part.add_header("Content-Disposition", "attachment", filename=path.name)
    return part


def _smtp_send(cfg, from_addr: str, recipients: list[str], message: str) -> None:
    context = ssl.create_default_context()
    port = cfg["port"]
    if port == 465:
        smtp_cls = smtplib.SMTP_SSL
        connect_kwargs = {"context": context, "timeout": 15}
    else:
        smtp_cls = smtplib.SMTP
        connect_kwargs = {"timeout": 15}

    with smtp_cls(cfg["host"], port, **connect_kwargs) as smtp:
        if port != 465 and cfg["use_tls"]:
            smtp.starttls(context=context)
        if cfg["user"] and cfg["password"]:
            smtp.login(cfg["user"], cfg["password"])
        smtp.sendmail(from_addr, recipients, message)


def send_email_with_pdf(
    config,
    to_emails: str | list[str],
    subject: str,
    pdf_path: str,
    *,
    env_fallback: bool = False,
) -> None:
    cfg = _resolve_email_config(config, env_fallback=env_fallback)
    if isinstance(to_emails, list):
        recipients = [e.strip() for e in to_emails if (e or "").strip()]
    else:
        recipients = [
            e.strip()
            for e in str(to_emails).replace(";", ",").replace("\n", ",").split(",")
            if e.strip()
        ]
    if not recipients:
        raise ValueError("recipient email is required")
    if not cfg["host"]:
        raise ValueError("smtp_host is required in the email notification channel")

    from_addr = cfg["from"] or cfg["user"]
    if not from_addr:
        raise ValueError("from address or smtp username is required in the email notification channel")

    msg = MIMEMultipart()
    msg["Subject"] = subject
    msg["From"] = cfg["from_header"] or from_addr
    msg["To"] = ", ".join(recipients)
    msg.attach(_pdf_attachment_part(pdf_path))
    _smtp_send(cfg, from_addr, recipients, msg.as_string())


def get_channel_by_id(channel_id) -> dict | None:
    if channel_id in (None, ""):
        return None
    try:
        channel_id = int(channel_id)
    except (TypeError, ValueError):
        return None
    with _db_lock:
        c = _db()
        row = c.execute(
            "SELECT id, name, type, config, events, enabled FROM notification_channels WHERE id=?",
            (channel_id,),
        ).fetchone()
        c.close()
    if not row:
        return None
    ch = dict(row)
    ch["enabled"] = bool(ch.get("enabled", 1))
    ch["config"] = json.loads(ch["config"]) if isinstance(ch["config"], str) else ch["config"]
    return ch


def _send_email(config, subject, message):
    cfg = _resolve_email_config(config)
    if not cfg["to"] or not cfg["host"]:
        raise ValueError("email to and smtp_host required")

    msg = MIMEText(message, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = cfg["from_header"] or cfg["from"]
    msg["To"] = cfg["to"]
    from_addr = cfg["from"] or cfg["user"]
    _smtp_send(cfg, from_addr, [cfg["to"]], msg.as_string())


def deliver_channel(channel, event, service_name, service_url, extra=None):
    cfg = json.loads(channel["config"]) if isinstance(channel["config"], str) else channel["config"]
    message = _format_alert(event, service_name, service_url, extra)
    subject = f"[Tech Monitoring] {service_name} — {event.upper()}"
    ctype = channel["type"]
    if ctype == "slack":
        _send_slack(cfg, message)
    elif ctype == "email":
        _send_email(cfg, subject, message)
    elif ctype == "webhook":
        _send_webhook(cfg, message, event, service_name, service_url, extra or {})
    else:
        raise ValueError(f"unsupported type: {ctype}")


def _dispatch(service_id, event, service_name, service_url, extra=None):
    for ch in get_channels_for_service(service_id):
        if event not in parse_events(ch["events"]):
            continue

        def _send(channel=ch):
            try:
                deliver_channel(channel, event, service_name, service_url, extra)
                log.info("Sent %s alert → %s (%s)", event, channel["name"], channel["type"])
            except Exception as e:
                log.error("Notify failed %s (%s): %s", channel["name"], channel["type"], e)

        threading.Thread(target=_send, daemon=True).start()


def notify_monitor_event(service_id, event, service_name, service_url, extra=None):
    if event not in NOTIFY_EVENTS:
        return
    _dispatch(service_id, event, service_name, service_url, extra)


def migrate_channels():
    """Drop invalid event names; keep user-selected events."""
    with _db_lock:
        c = _db()
        rows = c.execute("SELECT id, events FROM notification_channels").fetchall()
        for row in rows:
            ev = parse_events(row["events"])
            if not ev:
                ev = ["down", "up"]
            new_json = json.dumps(ev)
            if new_json != row["events"]:
                c.execute("UPDATE notification_channels SET events=? WHERE id=?", (new_json, row["id"]))
        c.commit()
        c.close()
    log.info("Notification channels migrated")


def validate_payload(d, *, require_config=True):
    name = (d.get("name") or "").strip()
    ctype = (d.get("type") or "").strip().lower()
    if not name:
        return None, ({"error": "name required"}, 400)
    if ctype not in NOTIFY_TYPES:
        return None, ({"error": f"type must be one of: {', '.join(sorted(NOTIFY_TYPES))}"}, 400)
    events = parse_events(d.get("events", ["down", "up"]))
    if not events:
        return None, ({"error": "at least one event required"}, 400)
    config = d.get("config") or {}
    if not isinstance(config, dict):
        return None, ({"error": "config must be an object"}, 400)
    if require_config:
        if ctype == "slack" and not (config.get("webhook_url") or "").strip():
            return None, ({"error": "slack webhook_url required"}, 400)
        if ctype == "webhook" and not (config.get("url") or "").strip():
            return None, ({"error": "webhook url required"}, 400)
        if ctype == "email":
            if not (config.get("to") or "").strip():
                return None, ({"error": "email to address required"}, 400)
            if not (config.get("smtp_host") or "").strip():
                return None, ({"error": "smtp_host required"}, 400)
    return {
        "name": name[:80],
        "type": ctype,
        "config": config,
        "events": events,
        "enabled": 1 if d.get("enabled", True) else 0,
    }, None


def register_routes(app):
    @app.route("/api/settings/notifications", methods=["GET"])
    def api_list_notifications():
        if not _current_user():
            return jsonify({"error": "login required"}), 401
        with _db_lock:
            c = _db()
            rows = c.execute("SELECT * FROM notification_channels ORDER BY id").fetchall()
            c.close()
        return jsonify([channel_row(r) for r in rows])

    @app.route("/api/settings/notifications/options", methods=["GET"])
    def api_notification_options():
        if not _current_user():
            return jsonify({"error": "login required"}), 401
        return jsonify(list_channel_options())

    @app.route("/api/settings/notifications", methods=["POST"])
    def api_create_notification():
        if not _current_user():
            return jsonify({"error": "login required"}), 401
        d = request.json or {}
        payload, err = validate_payload(d)
        if err:
            return jsonify(err[0]), err[1]
        with _db_lock:
            c = _db()
            cur = c.execute(
                """INSERT INTO notification_channels(name,type,config,events,enabled)
                   VALUES(?,?,?,?,?)""",
                (payload["name"], payload["type"], json.dumps(payload["config"]),
                 json.dumps(payload["events"]), payload["enabled"]),
            )
            nid = cur.lastrowid
            c.commit()
            row = c.execute("SELECT * FROM notification_channels WHERE id=?", (nid,)).fetchone()
            c.close()
        return jsonify({"ok": True, "channel": channel_row(row, mask=True)})

    @app.route("/api/settings/notifications/<int:nid>", methods=["PUT"])
    def api_update_notification(nid):
        if not _current_user():
            return jsonify({"error": "login required"}), 401
        d = request.json or {}
        with _db_lock:
            c = _db()
            existing = c.execute("SELECT * FROM notification_channels WHERE id=?", (nid,)).fetchone()
            if not existing:
                c.close()
                return jsonify({"error": "not found"}), 404
            old_cfg = json.loads(existing["config"]) if existing["config"] else {}
            merged = {
                "name": d.get("name", existing["name"]),
                "type": d.get("type", existing["type"]),
                "config": {**old_cfg, **(d.get("config") or {})},
                "events": d.get("events", parse_events(existing["events"])),
                "enabled": d.get("enabled", bool(existing["enabled"])),
            }
            if merged["type"] == "email" and not (merged["config"].get("smtp_pass") or "").strip():
                merged["config"]["smtp_pass"] = old_cfg.get("smtp_pass", "")
            if merged["type"] == "slack" and not (merged["config"].get("webhook_url") or "").strip():
                merged["config"]["webhook_url"] = old_cfg.get("webhook_url", "")
            if merged["type"] == "webhook" and not (merged["config"].get("url") or "").strip():
                merged["config"]["url"] = old_cfg.get("url", "")
            payload, err = validate_payload(merged, require_config=False)
            if err:
                c.close()
                return jsonify(err[0]), err[1]
            c.execute(
                """UPDATE notification_channels
                   SET name=?, type=?, config=?, events=?, enabled=?
                   WHERE id=?""",
                (payload["name"], payload["type"], json.dumps(payload["config"]),
                 json.dumps(payload["events"]), payload["enabled"], nid),
            )
            c.commit()
            row = c.execute("SELECT * FROM notification_channels WHERE id=?", (nid,)).fetchone()
            c.close()
        return jsonify({"ok": True, "channel": channel_row(row, mask=True)})

    @app.route("/api/settings/notifications/<int:nid>", methods=["DELETE"])
    def api_delete_notification(nid):
        if not _current_user():
            return jsonify({"error": "login required"}), 401
        with _db_lock:
            c = _db()
            row = c.execute("SELECT id FROM notification_channels WHERE id=?", (nid,)).fetchone()
            if not row:
                c.close()
                return jsonify({"error": "not found"}), 404
            c.execute("DELETE FROM notification_channels WHERE id=?", (nid,))
            c.commit()
            c.close()
        return jsonify({"ok": True})

    @app.route("/api/settings/notifications/<int:nid>/test", methods=["POST"])
    def api_test_notification(nid):
        if not _current_user():
            return jsonify({"error": "login required"}), 401
        with _db_lock:
            c = _db()
            row = c.execute("SELECT * FROM notification_channels WHERE id=?", (nid,)).fetchone()
            c.close()
        if not row:
            return jsonify({"error": "not found"}), 404
        channel = dict(row)
        test_events = [
            ("down", {"status_code": 503, "response_ms": 0}),
            ("up", {"status_code": 200, "response_ms": 42}),
        ]
        sent = []
        try:
            for event, extra in test_events:
                deliver_channel(
                    channel, event, "Test Monitor", "https://example.com/health", extra,
                )
                sent.append(event)
        except Exception as e:
            log.warning("Notification test failed id=%s: %s", nid, e)
            return jsonify({"error": str(e), "sent": sent}), 400
        return jsonify({
            "ok": True,
            "message": f"Test notifications sent ({', '.join(sent)})",
            "sent": sent,
        })
