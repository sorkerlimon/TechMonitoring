import ssl, socket, time, json, threading, datetime, sqlite3, os, re, secrets, hashlib, hmac, tempfile, shutil
import urllib.request, urllib.error
from pathlib import Path
from urllib.parse import urlparse
from flask import Flask, request, jsonify, send_from_directory, session, redirect, send_file, after_this_request
from werkzeug.exceptions import HTTPException

from database import db, DB_LOCK, DB_FILE, init_db
import notification
from report_pdf import fetch_service_report_stats, build_report_pdf, report_filename
from techlog import setup_logging, get_logger

setup_logging()
log = get_logger("app")

# ── Config ─────────────────────────────────────────────────────────────────────
PORT     = 8080
STATIC   = Path(__file__).parent / "static"
STATIC.mkdir(exist_ok=True)

app      = Flask(__name__, static_folder=str(STATIC))
app.secret_key = os.environ.get("UPTIME_SECRET_KEY", "dev-secret-change-this")
app.permanent_session_lifetime = datetime.timedelta(hours=1)
app.config["SESSION_REFRESH_EACH_REQUEST"] = False
THREADS  = {}   # service_id → thread stop_event
BOOT_LOCK = threading.Lock()
BOOTSTRAPPED = False

def has_admin_user():
    ensure_runtime_started()
    with DB_LOCK:
        c = db()
        r = c.execute("SELECT 1 FROM users WHERE is_admin=1 LIMIT 1").fetchone()
        c.close()
    return bool(r)

def hash_value(v):
    return hashlib.sha256(v.encode("utf-8")).hexdigest()

def current_user():
    ensure_runtime_started()
    uid = session.get("uid")
    if not uid:
        return None
    with DB_LOCK:
        c = db()
        r = c.execute("SELECT id, username, is_admin FROM users WHERE id=?", (uid,)).fetchone()
        c.close()
    return dict(r) if r else None

notification.configure(db, DB_LOCK, current_user)
notification.register_routes(app)

@app.after_request
def log_api_errors(response):
    if request.path.startswith("/api/") and response.status_code >= 400:
        log.warning("API %s %s → %s", request.method, request.path, response.status_code)
    return response

@app.errorhandler(Exception)
def log_unhandled_error(e):
    if isinstance(e, HTTPException):
        return e
    log.exception("Unhandled error on %s %s: %s", request.method, request.path, e)
    return jsonify({"error": "internal server error"}), 500

def api_key_from_request():
    k = request.headers.get("X-API-Key")
    if k:
        return k.strip()
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    q = request.args.get("api_key")
    return q.strip() if q else None

def validate_api_key(raw_key):
    if not raw_key:
        return False
    key_hash = hash_value(raw_key)
    with DB_LOCK:
        c = db()
        row = c.execute("""SELECT id FROM api_keys
                           WHERE key_hash=? AND active=1
                           LIMIT 1""", (key_hash,)).fetchone()
        if row:
            c.execute("UPDATE api_keys SET last_used_at=datetime('now') WHERE id=?", (row["id"],))
            c.commit()
        c.close()
    return bool(row)

def is_authenticated_request():
    if current_user():
        return True
    return validate_api_key(api_key_from_request())

def ensure_runtime_started():
    global BOOTSTRAPPED
    if BOOTSTRAPPED:
        return
    with BOOT_LOCK:
        if BOOTSTRAPPED:
            return
        init_db()
        notification.migrate_channels()
        start_all()
        BOOTSTRAPPED = True
        log.info("Runtime started — monitors active")

def make_password_hash(password):
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120000)
    return f"{salt}${digest.hex()}"

def verify_password(password, stored_hash):
    try:
        salt, digest_hex = stored_hash.split("$", 1)
    except ValueError:
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120000).hex()
    return hmac.compare_digest(digest, digest_hex)

def issue_api_key(name, created_by):
    raw = "tm_" + secrets.token_urlsafe(32)
    prefix = raw[:12]
    key_hash = hash_value(raw)
    with DB_LOCK:
        c = db()
        c.execute("""INSERT INTO api_keys(name, key_hash, key_prefix, created_by)
                     VALUES(?,?,?,?)""", (name, key_hash, prefix, created_by))
        c.commit()
        c.close()
    return raw, prefix

@app.before_request
def bootstrap_runtime():
    ensure_runtime_started()

@app.before_request
def enforce_api_auth():
    path = request.path or ""
    if not path.startswith("/api/"):
        return
    public_paths = {
        "/api/auth/status",
        "/api/auth/setup-admin",
        "/api/auth/login",
    }
    if path in public_paths:
        return
    if not has_admin_user() and path != "/api/auth/setup-admin":
        return jsonify({"error": "admin setup required"}), 403
    if not is_authenticated_request():
        return jsonify({"error": "unauthorized"}), 401

# ── Network ────────────────────────────────────────────────────────────────────

def check_url(url, timeout=30, method="GET"):
    start = time.perf_counter()
    try:
        req = urllib.request.Request(url, method=method,
              headers={"User-Agent": "UptimeMonitor/2.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            r.read()
            ms   = (time.perf_counter() - start) * 1000
            return True, round(ms, 2), r.status
    except urllib.error.HTTPError as e:
        ms = (time.perf_counter() - start) * 1000
        ok = e.code < 500
        return ok, round(ms, 2), e.code
    except Exception:
        ms = (time.perf_counter() - start) * 1000
        return False, round(ms, 2), None

def get_ssl_expiry(hostname):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((hostname, 443), timeout=10),
                             server_hostname=hostname) as s:
            exp = datetime.datetime.strptime(
                s.getpeercert()["notAfter"], "%b %d %H:%M:%S %Y %Z").date()
            return str(exp)
    except: return None

def get_domain_expiry(hostname):
    try:
        import whois
        import re

        if not hostname:
            return None

        w = whois.whois(hostname)
        exp = w.expiration_date
        if isinstance(exp, (list, tuple)):
            exp = next((d for d in exp if d), None)
        if isinstance(exp, datetime.datetime):
            return str(exp.date())
        if isinstance(exp, datetime.date):
            return str(exp)

        # Some WHOIS providers return text formats instead of datetime objects.
        if isinstance(exp, str):
            s = exp.strip()
            if not s:
                return None
            s = re.sub(r"([+-]\d{2}:?\d{2}|Z)$", "", s).strip()
            for fmt in (
                "%Y-%m-%d",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%d-%b-%Y",
                "%b %d %Y",
                "%d %b %Y",
            ):
                try:
                    return str(datetime.datetime.strptime(s, fmt).date())
                except ValueError:
                    pass
            # Fallback: pull an ISO-like date from mixed text.
            m = re.search(r"\d{4}-\d{2}-\d{2}", s)
            if m:
                return m.group(0)
    except Exception as e:
        log.warning("WHOIS lookup failed for %s: %s", hostname, e)
    return None

def days_until(s):
    if not s: return None
    try: return (datetime.date.fromisoformat(s) - datetime.date.today()).days
    except: return None

# ── Stats ──────────────────────────────────────────────────────────────────────

def uptime_pct(sid, hours):
    cutoff = time.time() - hours * 3600
    with DB_LOCK:
        c = db()
        r = c.execute("""SELECT COUNT(*) t, SUM(is_up) u FROM checks
                         WHERE service_id=? AND ts>=?""", (sid, cutoff)).fetchone()
        c.close()
    if not r or not r["t"]: return 100.0
    return round((r["u"] or 0) / r["t"] * 100, 2)

def avg_ms(sid, hours):
    cutoff = time.time() - hours * 3600
    with DB_LOCK:
        c = db()
        r = c.execute("""SELECT AVG(response_ms) a FROM checks
                         WHERE service_id=? AND ts>=? AND is_up=1""", (sid, cutoff)).fetchone()
        c.close()
    return round(r["a"], 2) if r and r["a"] else 0.0

def cert_info(sid):
    with DB_LOCK:
        c = db()
        r = c.execute("SELECT * FROM cert_info WHERE service_id=?", (sid,)).fetchone()
        c.close()
    if not r: return None, None
    return r["ssl_expiry"], r["domain_expiry"]

def save_cert(sid, ssl_e, dom_e):
    with DB_LOCK:
        c = db()
        c.execute("""INSERT INTO cert_info(service_id,ssl_expiry,domain_expiry,updated_at)
                     VALUES(?,?,?,datetime('now'))
                     ON CONFLICT(service_id) DO UPDATE SET
                        ssl_expiry=excluded.ssl_expiry,
                        domain_expiry=excluded.domain_expiry,
                        updated_at=excluded.updated_at""", (sid, ssl_e, dom_e))
        c.commit(); c.close()

def history_2h(sid):
    cutoff = time.time() - 7200
    with DB_LOCK:
        c = db()
        rows = c.execute("""SELECT ts, is_up, response_ms, status_code FROM checks
                            WHERE service_id=? AND ts>=? ORDER BY ts ASC LIMIT 200""",
                         (sid, cutoff)).fetchall()
        c.close()
    return [{"ts": r["ts"], "ok": bool(r["is_up"]),
             "ms": r["response_ms"], "code": r["status_code"]} for r in rows]

def chart_history(sid, range_key="1d", max_points=400):
    range_key = normalize_range_key(range_key, default="1d")
    range_seconds = range_to_seconds(range_key)
    cutoff = time.time() - range_seconds
    to_ts = time.time()
    max_points = max(1, min(5000, int(max_points)))

    with DB_LOCK:
        c = db()
        if range_seconds <= 15 * 60:
            rows = c.execute("""SELECT ts, is_up, response_ms, status_code FROM checks
                                WHERE service_id=? AND ts>=? AND ts<=?
                                ORDER BY ts ASC
                                LIMIT ?""",
                             (sid, cutoff, to_ts, max_points)).fetchall()
        else:
            bucket = max(1, int(range_seconds / max_points))
            rows = c.execute("""SELECT
                                    (CAST(ts AS INTEGER) / ?) * ? AS bucket_ts,
                                    AVG(response_ms) AS ms,
                                    MIN(is_up) AS is_up,
                                    MAX(status_code) AS status_code
                                FROM checks
                                WHERE service_id=? AND ts>=? AND ts<=?
                                GROUP BY bucket_ts
                                ORDER BY bucket_ts ASC""",
                             (bucket, bucket, sid, cutoff, to_ts)).fetchall()
        c.close()

    if range_seconds <= 15 * 60:
        return [{
            "ts": r["ts"],
            "ok": bool(r["is_up"]),
            "ms": r["response_ms"],
            "code": r["status_code"],
        } for r in rows]
    return [{
        "ts": r["bucket_ts"],
        "ok": bool(r["is_up"]),
        "ms": round(r["ms"], 2) if r["ms"] is not None else 0,
        "code": r["status_code"],
    } for r in rows]

def range_to_seconds(range_key):
    key = normalize_range_key(range_key, default="2h")
    m = re.fullmatch(r"(\d+)([mhd])", key)
    if not m:
        return 2 * 3600
    n = int(m.group(1))
    unit = m.group(2)
    if unit == "m":
        return n * 60
    if unit == "h":
        return n * 3600
    return n * 24 * 3600

def normalize_range_key(range_key, default="2h"):
    if not range_key:
        return default
    key = str(range_key).strip().lower().replace(" ", "")
    if not key:
        return default

    # Pure number -> hours (e.g. "2" => "2h").
    if key.isdigit():
        n = int(key)
        return f"{n}h" if n > 0 else default

    # Normalize textual forms:
    # 5min, 5mins, 5minute, 5minutes -> 5m
    # 2hr, 2hrs, 2hour, 2hours -> 2h
    # 1day, 3days -> 1d / 3d
    key = re.sub(r"minutes?$", "m", key)
    key = re.sub(r"mins?$", "m", key)
    key = re.sub(r"hours?$", "h", key)
    key = re.sub(r"hrs?$", "h", key)
    key = re.sub(r"days?$", "d", key)

    m = re.fullmatch(r"(\d+)([mhd])", key)
    if not m:
        return default
    n = int(m.group(1))
    if n <= 0:
        return default
    return f"{n}{m.group(2)}"

def _parse_dt_param(s):
    if not s:
        return None
    s = str(s).strip()
    if not s:
        return None
    s = re.sub(r"([+-]\d{2}:?\d{2}|Z)$", "", s).strip()
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M",
    ):
        try:
            return datetime.datetime.strptime(s, fmt)
        except ValueError:
            pass
    try:
        return datetime.datetime.fromisoformat(s)
    except ValueError:
        pass
    try:
        d = datetime.date.fromisoformat(s)
        return datetime.datetime(d.year, d.month, d.day, 0, 0, 0)
    except ValueError:
        return None

def _parse_time_range_args(args):
    """
    Query params:
      - start/end (preferred)
      - from/to (aliases)
    Values may be ISO date (YYYY-MM-DD) or datetime.
    If end/to is a date, it becomes end-of-day.
    Returns (from_ts, to_ts) or (None, None).
    """
    start_raw = args.get("start") or args.get("from")
    end_raw = args.get("end") or args.get("to")

    start_dt = _parse_dt_param(start_raw)
    end_dt = _parse_dt_param(end_raw)

    if not start_dt and not end_dt:
        return None, None

    if end_dt and end_raw and re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(end_raw).strip()):
        end_dt = end_dt + datetime.timedelta(days=1) - datetime.timedelta(microseconds=1)

    if start_dt and end_dt and end_dt < start_dt:
        start_dt, end_dt = end_dt, start_dt

    return (start_dt.timestamp() if start_dt else None), (end_dt.timestamp() if end_dt else None)

def range_stats(sid, range_key="2h"):
    cutoff = time.time() - range_to_seconds(range_key)
    to_ts = time.time()
    with DB_LOCK:
        c = db()
        r = c.execute("""SELECT
                            COUNT(*) AS total_checks,
                            SUM(is_up) AS up_checks,
                            AVG(CASE WHEN is_up=1 THEN response_ms END) AS avg_response_ms
                         FROM checks
                         WHERE service_id=? AND ts>=? AND ts<=?""", (sid, cutoff, to_ts)).fetchone()
        last = c.execute("""SELECT ts, is_up, response_ms, status_code
                            FROM checks
                            WHERE service_id=? AND ts>=? AND ts<=?
                            ORDER BY ts DESC LIMIT 1""", (sid, cutoff, to_ts)).fetchone()
        c.close()

    total = int(r["total_checks"] or 0) if r else 0
    up = int(r["up_checks"] or 0) if r else 0
    down = max(0, total - up)
    uptime = round((up / total) * 100, 2) if total else 100.0
    downtime = round(max(0.0, 100.0 - uptime), 2)
    avg = round(r["avg_response_ms"], 2) if r and r["avg_response_ms"] else 0.0
    return {
        "range": range_key,
        "from_ts": cutoff,
        "to_ts": to_ts,
        "total_checks": total,
        "up_checks": up,
        "down_checks": down,
        "uptime_pct": uptime,
        "downtime_pct": downtime,
        "avg_response_ms": avg,
        "last_in_range": {
            "ts": last["ts"],
            "ok": bool(last["is_up"]),
            "ms": last["response_ms"],
            "code": last["status_code"],
        } if last else None,
    }

def range_stats_between(sid, from_ts, to_ts):
    with DB_LOCK:
        c = db()
        r = c.execute("""SELECT
                            COUNT(*) AS total_checks,
                            SUM(is_up) AS up_checks,
                            AVG(CASE WHEN is_up=1 THEN response_ms END) AS avg_response_ms
                         FROM checks
                         WHERE service_id=? AND ts>=? AND ts<=?""", (sid, from_ts, to_ts)).fetchone()
        last = c.execute("""SELECT ts, is_up, response_ms, status_code
                            FROM checks
                            WHERE service_id=? AND ts>=? AND ts<=?
                            ORDER BY ts DESC LIMIT 1""", (sid, from_ts, to_ts)).fetchone()
        c.close()

    total = int(r["total_checks"] or 0) if r else 0
    up = int(r["up_checks"] or 0) if r else 0
    down = max(0, total - up)
    uptime = round((up / total) * 100, 2) if total else 100.0
    downtime = round(max(0.0, 100.0 - uptime), 2)
    avg = round(r["avg_response_ms"], 2) if r and r["avg_response_ms"] else 0.0
    return {
        "from_ts": from_ts,
        "to_ts": to_ts,
        "total_checks": total,
        "up_checks": up,
        "down_checks": down,
        "uptime_pct": uptime,
        "downtime_pct": downtime,
        "avg_response_ms": avg,
        "last_in_range": {
            "ts": last["ts"],
            "ok": bool(last["is_up"]),
            "ms": last["response_ms"],
            "code": last["status_code"],
        } if last else None,
    }

def paginated_checks(sid, range_key="2h", page=1, page_size=50):
    cutoff = time.time() - range_to_seconds(range_key)
    to_ts = time.time()
    page = max(1, int(page))
    page_size = max(1, min(500, int(page_size)))
    offset = (page - 1) * page_size

    with DB_LOCK:
        c = db()
        total_row = c.execute("""SELECT COUNT(*) AS n FROM checks
                                 WHERE service_id=? AND ts>=? AND ts<=?""", (sid, cutoff, to_ts)).fetchone()
        rows = c.execute("""SELECT ts, is_up, response_ms, status_code FROM checks
                            WHERE service_id=? AND ts>=? AND ts<=?
                            ORDER BY ts DESC
                            LIMIT ? OFFSET ?""",
                         (sid, cutoff, to_ts, page_size, offset)).fetchall()
        c.close()

    total = int(total_row["n"] if total_row else 0)
    total_pages = max(1, (total + page_size - 1) // page_size)
    items = [{
        "ts": r["ts"],
        "ok": bool(r["is_up"]),
        "ms": r["response_ms"],
        "code": r["status_code"],
    } for r in rows]
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "range": range_key,
        "from_ts": cutoff,
        "to_ts": to_ts,
    }

def _normalize_order(order_by, order_direction, *, default_by="ts", default_dir="DESC"):
    by = (order_by or default_by)
    by = str(by).strip().lower()
    allowed = {
        "datetime": "ts",
        "checked_at": "ts",
        "ts": "ts",
        "response_ms": "response_ms",
        "status_code": "status_code",
        "is_up": "is_up",
        "id": "id",
    }
    col = allowed.get(by, allowed.get(default_by, "ts"))

    d = (order_direction or default_dir)
    d = str(d).strip().upper()
    if d not in ("ASC", "DESC"):
        d = default_dir
    return col, d

def paginated_checks_between(sid, from_ts, to_ts, page=1, page_size=50, order_by="ts", order_direction="DESC"):
    page = max(1, int(page))
    page_size = max(1, min(500, int(page_size)))
    offset = (page - 1) * page_size

    col, direction = _normalize_order(order_by, order_direction, default_by="ts", default_dir="DESC")
    with DB_LOCK:
        c = db()
        total_row = c.execute("""SELECT COUNT(*) AS n FROM checks
                                 WHERE service_id=? AND ts>=? AND ts<=?""",
                              (sid, from_ts, to_ts)).fetchone()
        q = f"""SELECT ts, is_up, response_ms, status_code FROM checks
                WHERE service_id=? AND ts>=? AND ts<=?
                ORDER BY {col} {direction}
                LIMIT ? OFFSET ?"""
        rows = c.execute(q, (sid, from_ts, to_ts, page_size, offset)).fetchall()
        c.close()

    total = int(total_row["n"] if total_row else 0)
    total_pages = max(1, (total + page_size - 1) // page_size)
    items = [{
        "ts": r["ts"],
        "ok": bool(r["is_up"]),
        "ms": r["response_ms"],
        "code": r["status_code"],
    } for r in rows]
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "from_ts": from_ts,
        "to_ts": to_ts,
        "order_by": col,
        "order_direction": direction,
    }

def checks_history_by_range(sid, range_key="2h", limit=2000):
    cutoff = time.time() - range_to_seconds(range_key)
    to_ts = time.time()
    limit = max(1, min(5000, int(limit)))
    with DB_LOCK:
        c = db()
        rows = c.execute("""SELECT ts, is_up, response_ms, status_code FROM checks
                            WHERE service_id=? AND ts>=? AND ts<=?
                            ORDER BY ts ASC
                            LIMIT ?""", (sid, cutoff, to_ts, limit)).fetchall()
        c.close()
    return [{
        "checked_at": datetime.datetime.fromtimestamp(r["ts"]).strftime("%Y-%m-%d %H:%M:%S"),
        "ok": bool(r["is_up"]),
        "ms": r["response_ms"],
        "code": r["status_code"],
    } for r in rows]

def checks_history_between(
    sid,
    from_ts,
    to_ts,
    limit=2000,
    order_by="ts",
    order_direction="ASC",
    page=None,
    page_size=None,
):
    limit = max(1, min(5000, int(limit)))
    col, direction = _normalize_order(order_by, order_direction, default_by="ts", default_dir="ASC")

    use_pagination = page is not None or page_size is not None
    if use_pagination:
        try:
            page = int(page or 1)
        except (TypeError, ValueError):
            page = 1
        try:
            page_size = int(page_size or 200)
        except (TypeError, ValueError):
            page_size = 200
        page = max(1, page)
        page_size = max(1, min(5000, page_size))
        offset = (page - 1) * page_size
        effective_limit = min(limit, page_size)
    else:
        page = None
        page_size = None
        offset = 0
        effective_limit = limit

    with DB_LOCK:
        c = db()
        q = f"""SELECT ts, is_up, response_ms, status_code FROM checks
                WHERE service_id=? AND ts>=? AND ts<=?
                ORDER BY {col} {direction}
                LIMIT ? OFFSET ?"""
        rows = c.execute(q, (sid, from_ts, to_ts, effective_limit, offset)).fetchall()
        c.close()

    items = [{
        "checked_at": datetime.datetime.fromtimestamp(r["ts"]).strftime("%Y-%m-%d %H:%M:%S"),
        "ok": bool(r["is_up"]),
        "ms": r["response_ms"],
        "code": r["status_code"],
    } for r in rows]

    if use_pagination:
        with DB_LOCK:
            c = db()
            total_row = c.execute("""SELECT COUNT(*) AS n FROM checks
                                     WHERE service_id=? AND ts>=? AND ts<=?""",
                                  (sid, from_ts, to_ts)).fetchone()
            c.close()
        total = int(total_row["n"] if total_row else 0)
        total_pages = max(1, (total + page_size - 1) // page_size)
        return {
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "from_ts": from_ts,
            "to_ts": to_ts,
            "order_by": col,
            "order_direction": direction,
        }

    return items

def heartbeat_bars(sid, count=50):
    """Last N check results for the heartbeat bar."""
    with DB_LOCK:
        c = db()
        rows = c.execute("""SELECT ts, is_up FROM checks
                            WHERE service_id=? ORDER BY ts DESC LIMIT ?""",
                         (sid, count)).fetchall()
        c.close()
    return [{"ts": r["ts"], "ok": bool(r["is_up"])} for r in reversed(rows)]

def last_check_row(sid):
    with DB_LOCK:
        c = db()
        r = c.execute("""SELECT is_up, response_ms, status_code, ts FROM checks
                         WHERE service_id=? ORDER BY ts DESC LIMIT 1""", (sid,)).fetchone()
        c.close()
    if not r: return None
    return dict(r)

# ── Monitor thread ─────────────────────────────────────────────────────────────

def monitor_loop(sid, name, url, interval, retries, timeout, method, stop_evt):
    log.info("Monitor started id=%s name=%s url=%s interval=%ss", sid, name, url, interval)
    hostname = urlparse(url).hostname
    ssl_e  = get_ssl_expiry(hostname)
    dom_e  = get_domain_expiry(hostname)
    save_cert(sid, ssl_e, dom_e)
    notification.check_expiry_alerts(sid, name, url, ssl_e, dom_e)
    last_cert = time.time()

    prev = last_check_row(sid)
    if prev is not None:
        notification.seed_service_state(sid, bool(prev["is_up"]))

    try:
        while not stop_evt.is_set():
            is_up, ms, code = check_url(url, timeout, method)

            # Retry logic
            if not is_up and retries > 0:
                for _ in range(retries):
                    time.sleep(2)
                    is_up, ms, code = check_url(url, timeout, method)
                    if is_up: break

            ts = time.time()
            with DB_LOCK:
                c = db()
                c.execute("""INSERT INTO checks(service_id,ts,is_up,response_ms,status_code)
                             VALUES(?,?,?,?,?)""",
                          (sid, ts, 1 if is_up else 0, ms, code))
                c.commit(); c.close()

            log.debug("[%s] %s %7.1fms code=%s", name, "UP" if is_up else "DOWN", ms, code or "-")

            notification.handle_check_result(sid, is_up, name, url, status_code=code, response_ms=ms)

            if time.time() - last_cert > 21600:
                ssl_e = get_ssl_expiry(hostname)
                dom_e = get_domain_expiry(hostname)
                save_cert(sid, ssl_e, dom_e)
                notification.check_expiry_alerts(sid, name, url, ssl_e, dom_e)
                last_cert = time.time()

            stop_evt.wait(interval)
    except Exception as e:
        log.exception("Monitor crashed id=%s name=%s: %s", sid, name, e)
    finally:
        log.info("Monitor stopped id=%s name=%s", sid, name)

def start_service(sid):
    with DB_LOCK:
        c = db()
        r = c.execute("SELECT * FROM services WHERE id=? AND enabled=1 AND paused=0",
                      (sid,)).fetchone()
        c.close()
    if not r: return
    if sid in THREADS:
        THREADS[sid].set()
        del THREADS[sid]
    notification.clear_service_state(sid)
    evt = threading.Event()
    THREADS[sid] = evt
    t = threading.Thread(target=monitor_loop,
        args=(r["id"], r["name"], r["url"], r["interval"],
              r["retries"], r["timeout"], r["method"], evt),
        daemon=True)
    t.start()

def stop_service(sid):
    if sid in THREADS:
        THREADS[sid].set()
        del THREADS[sid]
    notification.clear_service_state(sid)

def start_all():
    with DB_LOCK:
        c = db()
        rows = c.execute("SELECT id FROM services WHERE enabled=1 AND paused=0").fetchall()
        c.close()
    for r in rows:
        start_service(r["id"])

# ── Service data builder ───────────────────────────────────────────────────────

def build_service(sid=None):
    with DB_LOCK:
        c = db()
        if sid:
            rows = c.execute("SELECT * FROM services WHERE id=?", (sid,)).fetchall()
        else:
            rows = c.execute("SELECT * FROM services ORDER BY id").fetchall()
        c.close()

    result = []
    for r in rows:
        lc  = last_check_row(r["id"])
        ssl_e, dom_e = cert_info(r["id"])
        result.append({
            "id":           r["id"],
            "name":         r["name"],
            "url":          r["url"],
            "interval":     r["interval"],
            "retries":      r["retries"],
            "timeout":      r["timeout"],
            "method":       r["method"],
            "paused":       bool(r["paused"]),
            "current_up":   bool(lc["is_up"]) if lc else None,
            "current_ms":   lc["response_ms"] if lc else None,
            "status_code":  lc["status_code"] if lc else None,
            "last_check_ts":lc["ts"] if lc else None,
            "avg_ms_24h":   avg_ms(r["id"], 24),
            "uptime_24h":   uptime_pct(r["id"], 24),
            "uptime_30d":   uptime_pct(r["id"], 24*30),
            "uptime_1y":    uptime_pct(r["id"], 24*365),
            "ssl_expiry":   ssl_e,
            "ssl_days":     days_until(ssl_e),
            "domain_expiry":dom_e,
            "domain_days":  days_until(dom_e),
            "heartbeat":    heartbeat_bars(r["id"]),
            "history":      history_2h(r["id"]),
            "notification_channels": notification.get_service_channel_ids(r["id"]),
        })
    return result[0] if (sid and result) else result

# ── API Routes ─────────────────────────────────────────────────────────────────

@app.route("/api/auth/status", methods=["GET"])
def api_auth_status():
    u = current_user()
    return jsonify({
        "admin_exists": has_admin_user(),
        "logged_in": bool(u),
        "user": {"id": u["id"], "username": u["username"], "is_admin": bool(u["is_admin"])} if u else None
    })

@app.route("/api/auth/setup-admin", methods=["POST"])
def api_auth_setup_admin():
    if has_admin_user():
        return jsonify({"error": "admin already exists"}), 409
    d = request.json or {}
    username = (d.get("username") or "").strip()
    password = d.get("password") or ""
    if len(username) < 3 or len(password) < 6:
        return jsonify({"error": "username >= 3 and password >= 6 required"}), 400
    pw_hash = make_password_hash(password)
    with DB_LOCK:
        c = db()
        try:
            cur = c.execute("""INSERT INTO users(username, password_hash, is_admin)
                               VALUES(?,?,1)""", (username, pw_hash))
            uid = cur.lastrowid
            c.commit()
        except sqlite3.IntegrityError:
            c.close()
            return jsonify({"error": "username already exists"}), 409
        c.close()
    session["uid"] = uid
    session.permanent = True
    return jsonify({"ok": True, "username": username})

@app.route("/api/auth/login", methods=["POST"])
def api_auth_login():
    d = request.json or {}
    username = (d.get("username") or "").strip()
    password = d.get("password") or ""
    with DB_LOCK:
        c = db()
        r = c.execute("""SELECT id, username, password_hash, is_admin FROM users
                         WHERE lower(username)=lower(?) LIMIT 1""", (username,)).fetchone()
        c.close()
    if not r or not verify_password(password, r["password_hash"]):
        return jsonify({"error": "invalid credentials"}), 401
    session["uid"] = r["id"]
    session.permanent = True
    return jsonify({"ok": True, "username": r["username"], "is_admin": bool(r["is_admin"])})

@app.route("/api/auth/logout", methods=["POST"])
def api_auth_logout():
    session.clear()
    return jsonify({"ok": True})

@app.route("/api/settings/api-keys", methods=["GET"])
def api_list_keys():
    u = current_user()
    if not u:
        return jsonify({"error": "login required"}), 401
    with DB_LOCK:
        c = db()
        rows = c.execute("""SELECT id, name, key_prefix, active, created_at, last_used_at
                            FROM api_keys ORDER BY id DESC""").fetchall()
        c.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/settings/api-keys", methods=["POST"])
def api_create_key():
    u = current_user()
    if not u:
        return jsonify({"error": "login required"}), 401
    d = request.json or {}
    name = (d.get("name") or "default").strip()[:80] or "default"
    raw, prefix = issue_api_key(name=name, created_by=u["id"])
    return jsonify({"ok": True, "name": name, "key_prefix": prefix, "api_key": raw})

@app.route("/api/settings/api-keys/<int:key_id>", methods=["DELETE"])
def api_delete_key(key_id):
    u = current_user()
    if not u:
        return jsonify({"error": "login required"}), 401
    with DB_LOCK:
        c = db()
        row = c.execute("SELECT id FROM api_keys WHERE id=?", (key_id,)).fetchone()
        if not row:
            c.close()
            return jsonify({"error": "key not found"}), 404
        c.execute("DELETE FROM api_keys WHERE id=?", (key_id,))
        c.commit()
        c.close()
    return jsonify({"ok": True})

@app.route("/api/settings/users", methods=["GET"])
def api_list_users():
    u = current_user()
    if not u:
        return jsonify({"error": "login required"}), 401
    if not u["is_admin"]:
        return jsonify({"error": "admin privileges required"}), 403
    with DB_LOCK:
        c = db()
        rows = c.execute("""SELECT id, username, is_admin, created_at
                            FROM users ORDER BY id""").fetchall()
        c.close()
    return jsonify([{
        "id": r["id"],
        "username": r["username"],
        "is_admin": bool(r["is_admin"]),
        "created_at": r["created_at"],
        "is_self": r["id"] == u["id"],
    } for r in rows])

@app.route("/api/settings/users", methods=["POST"])
def api_create_user():
    u = current_user()
    if not u:
        return jsonify({"error": "login required"}), 401
    if not u["is_admin"]:
        return jsonify({"error": "admin privileges required"}), 403
    d = request.json or {}
    username = (d.get("username") or "").strip()
    password = d.get("password") or ""
    is_admin = 1 if d.get("is_admin") else 0
    if len(username) < 3 or len(password) < 6:
        return jsonify({"error": "username >= 3 and password >= 6 required"}), 400
    pw_hash = make_password_hash(password)
    with DB_LOCK:
        c = db()
        try:
            cur = c.execute("""INSERT INTO users(username, password_hash, is_admin)
                               VALUES(?,?,?)""", (username, pw_hash, is_admin))
            uid = cur.lastrowid
            c.commit()
        except sqlite3.IntegrityError:
            c.close()
            return jsonify({"error": "username already exists"}), 409
        c.close()
    return jsonify({"ok": True, "id": uid, "username": username, "is_admin": bool(is_admin)})

@app.route("/api/settings/users/<int:user_id>", methods=["PUT"])
def api_update_user(user_id):
    u = current_user()
    if not u:
        return jsonify({"error": "login required"}), 401
    if user_id != u["id"] and not u["is_admin"]:
        return jsonify({"error": "admin privileges required"}), 403
    d = request.json or {}
    password = d.get("password") or ""
    if "is_admin" in d and not u["is_admin"]:
        return jsonify({"error": "admin privileges required"}), 403
    is_admin = 1 if d.get("is_admin") else 0 if "is_admin" in d else None

    with DB_LOCK:
        c = db()
        target = c.execute("SELECT id, is_admin FROM users WHERE id=?", (user_id,)).fetchone()
        if not target:
            c.close()
            return jsonify({"error": "user not found"}), 404
        if is_admin is not None and target["is_admin"] and not is_admin:
            admin_count = c.execute("SELECT COUNT(*) n FROM users WHERE is_admin=1").fetchone()["n"]
            if admin_count <= 1:
                c.close()
                return jsonify({"error": "cannot remove the last admin"}), 400
        if password:
            if len(password) < 6:
                c.close()
                return jsonify({"error": "password must be at least 6 characters"}), 400
            c.execute("UPDATE users SET password_hash=? WHERE id=?",
                      (make_password_hash(password), user_id))
        if is_admin is not None:
            c.execute("UPDATE users SET is_admin=? WHERE id=?", (is_admin, user_id))
        if not password and is_admin is None:
            c.close()
            return jsonify({"error": "nothing to update"}), 400
        c.commit()
        c.close()
    return jsonify({"ok": True})

@app.route("/api/settings/users/<int:user_id>", methods=["DELETE"])
def api_delete_user(user_id):
    u = current_user()
    if not u:
        return jsonify({"error": "login required"}), 401
    if not u["is_admin"]:
        return jsonify({"error": "admin privileges required"}), 403
    if user_id == u["id"]:
        return jsonify({"error": "you cannot delete your own account"}), 400
    with DB_LOCK:
        c = db()
        target = c.execute("SELECT id, is_admin FROM users WHERE id=?", (user_id,)).fetchone()
        if not target:
            c.close()
            return jsonify({"error": "user not found"}), 404
        if target["is_admin"]:
            admin_count = c.execute("SELECT COUNT(*) n FROM users WHERE is_admin=1").fetchone()["n"]
            if admin_count <= 1:
                c.close()
                return jsonify({"error": "cannot delete the last admin"}), 400
        c.execute("DELETE FROM users WHERE id=?", (user_id,))
        c.commit()
        c.close()
    return jsonify({"ok": True})

@app.route("/api/services", methods=["GET"])
def api_list():
    return jsonify(build_service())

@app.route("/api/services/<int:sid>", methods=["GET"])
def api_detail(sid):
    data = build_service(sid)
    if not data: return jsonify({"error": "not found"}), 404
    return jsonify(data)

@app.route("/api/services/<int:sid>/history", methods=["GET"])
def api_service_history(sid):
    with DB_LOCK:
        c = db()
        exists = c.execute("SELECT 1 FROM services WHERE id=? LIMIT 1", (sid,)).fetchone()
        c.close()
    if not exists:
        return jsonify({"error": "not found"}), 404

    range_key = normalize_range_key(request.args.get("range", "1d"), default="1d")
    try:
        max_points = int(request.args.get("max_points", 400))
    except (TypeError, ValueError):
        max_points = 400
    items = chart_history(sid, range_key=range_key, max_points=max_points)
    return jsonify({
        "range": range_key,
        "from_ts": time.time() - range_to_seconds(range_key),
        "to_ts": time.time(),
        "items": items,
    })

@app.route("/api/services/<int:sid>/checks", methods=["GET"])
def api_checks(sid):
    with DB_LOCK:
        c = db()
        exists = c.execute("SELECT 1 FROM services WHERE id=? LIMIT 1", (sid,)).fetchone()
        c.close()
    if not exists:
        return jsonify({"error": "not found"}), 404

    from_ts, to_ts = _parse_time_range_args(request.args)
    range_key = normalize_range_key(request.args.get("range", "2h"), default="2h")

    try:
        page = int(request.args.get("page", 1))
    except (TypeError, ValueError):
        page = 1
    try:
        page_size = int(request.args.get("page_size", 50))
    except (TypeError, ValueError):
        page_size = 50

    order_by = request.args.get("order_by", "ts")
    order_direction = request.args.get("order_direction", "DESC")

    if from_ts is not None or to_ts is not None:
        if from_ts is None:
            from_ts = 0.0
        if to_ts is None:
            to_ts = time.time()
        data = paginated_checks_between(
            sid,
            from_ts=from_ts,
            to_ts=to_ts,
            page=page,
            page_size=page_size,
            order_by=order_by,
            order_direction=order_direction,
        )
        data["range"] = None
    else:
        # existing helper defaults to ts DESC internally
        data = paginated_checks(sid, range_key=range_key, page=page, page_size=page_size)
    return jsonify(data)

@app.route("/api/services/by-name/<string:friendly_name>", methods=["GET"])
def api_service_by_name(friendly_name):
    with DB_LOCK:
        c = db()
        row = c.execute("""SELECT id, interval FROM services
                           WHERE lower(trim(name)) = lower(trim(?))
                           LIMIT 1""", (friendly_name,)).fetchone()
        c.close()
    if not row:
        return jsonify({"error": "service not found", "friendly_name": friendly_name}), 404

    sid = row["id"]
    interval = row["interval"]

    from_ts, to_ts = _parse_time_range_args(request.args)
    range_key = normalize_range_key(request.args.get("range", "1h"), default="1h")
    try:
        history_limit = int(request.args.get("history_limit", 2000))
    except (TypeError, ValueError):
        history_limit = 2000
    try:
        history_page = int(request.args.get("page", 1))
    except (TypeError, ValueError):
        history_page = 1
    try:
        history_page_size = int(request.args.get("page_size", 200))
    except (TypeError, ValueError):
        history_page_size = 200
    history_order_by = request.args.get("order_by", "ts")
    history_order_direction = request.args.get("order_direction", "ASC")

    if from_ts is not None or to_ts is not None:
        if from_ts is None:
            from_ts = 0.0
        if to_ts is None:
            to_ts = time.time()
        stats = range_stats_between(sid, from_ts=from_ts, to_ts=to_ts)
        stats["range"] = None
    else:
        stats = range_stats(sid, range_key=range_key)
    ssl_e, dom_e = cert_info(sid)
    if from_ts is not None or to_ts is not None:
        history = checks_history_between(
            sid,
            from_ts=from_ts,
            to_ts=to_ts,
            limit=history_limit,
            order_by=history_order_by,
            order_direction=history_order_direction,
            page=history_page,
            page_size=history_page_size,
        )
    else:
        history = checks_history_by_range(sid, range_key=range_key, limit=history_limit)

    return jsonify({
        "friendly_name": friendly_name,
        "check_interval_seconds": interval,
        "range": None if (from_ts is not None or to_ts is not None) else range_key,
        "from_ts": from_ts,
        "to_ts": to_ts,
        "uptime_pct": stats["uptime_pct"],
        "downtime_pct": stats["downtime_pct"],
        "certificate_expiry": ssl_e,
        "domain_expiry": dom_e,
        "history": history,
    })

@app.route("/api/services", methods=["POST"])
def api_add():
    d = request.json
    name     = d.get("name","").strip()
    url      = d.get("url","").strip()
    interval = int(d.get("interval", 60))
    retries  = int(d.get("retries", 0))
    timeout  = int(d.get("timeout", 30))
    method   = d.get("method", "GET").upper()
    if not name or not url:
        return jsonify({"error": "name and url required"}), 400
    try:
        with DB_LOCK:
            c = db()
            cur = c.execute("""INSERT INTO services(name,url,interval,retries,timeout,method)
                               VALUES(?,?,?,?,?,?)""",
                            (name, url, interval, retries, timeout, method))
            sid = cur.lastrowid
            c.commit(); c.close()
        notification.set_service_channels(sid, d.get("notification_channels", []))
        start_service(sid)
        log.info("Monitor created id=%s name=%s url=%s", sid, name, url)
        return jsonify({"ok": True, "id": sid})
    except sqlite3.IntegrityError:
        log.warning("Monitor create failed — duplicate URL: %s", url)
        return jsonify({"error": "URL already exists"}), 409

@app.route("/api/services/<int:sid>", methods=["PUT"])
def api_edit(sid):
    d = request.json
    with DB_LOCK:
        c = db()
        c.execute("""UPDATE services SET name=?,url=?,interval=?,retries=?,timeout=?,method=?
                     WHERE id=?""",
                  (d["name"], d["url"], d["interval"], d["retries"],
                   d["timeout"], d.get("method","GET"), sid))
        c.commit(); c.close()
    if "notification_channels" in d:
        notification.set_service_channels(sid, d.get("notification_channels", []))
    stop_service(sid)
    start_service(sid)
    log.info("Monitor updated id=%s", sid)
    return jsonify({"ok": True})

@app.route("/api/services/<int:sid>", methods=["DELETE"])
def api_delete(sid):
    stop_service(sid)
    with DB_LOCK:
        c = db()
        c.execute("DELETE FROM checks    WHERE service_id=?", (sid,))
        c.execute("DELETE FROM cert_info WHERE service_id=?", (sid,))
        c.execute("DELETE FROM services  WHERE id=?", (sid,))
        c.commit(); c.close()
    log.info("Monitor deleted id=%s", sid)
    return jsonify({"ok": True})

@app.route("/api/services/<int:sid>/pause", methods=["POST"])
def api_pause(sid):
    paused = request.json.get("paused", True)
    with DB_LOCK:
        c = db()
        c.execute("UPDATE services SET paused=? WHERE id=?", (1 if paused else 0, sid))
        c.commit(); c.close()
    if paused: stop_service(sid)
    else:      start_service(sid)
    return jsonify({"ok": True})

@app.route("/api/db-stats")
def api_db_stats():
    with DB_LOCK:
        c = db()
        total = c.execute("SELECT COUNT(*) n FROM checks").fetchone()["n"]
        svcs  = c.execute("SELECT COUNT(*) n FROM services").fetchone()["n"]
        size  = os.path.getsize(DB_FILE) if os.path.exists(DB_FILE) else 0
        c.close()
    return jsonify({"checks": total, "services": svcs,
                    "db_file": DB_FILE, "db_size_kb": round(size/1024,1)})

# ── Static pages ───────────────────────────────────────────────────────────────

@app.route("/")
def index():
    if not has_admin_user() or not current_user():
        return redirect("/login")
    return send_from_directory(STATIC, "index.html")

@app.route("/login")
def login_page():
    return send_from_directory(STATIC, "login.html")

@app.route("/service/<int:sid>")
def service_page(sid):
    if not has_admin_user() or not current_user():
        return redirect("/login")
    return send_from_directory(STATIC, "service.html")

@app.route("/settings")
def settings_page():
    if not current_user():
        return redirect("/login")
    return send_from_directory(STATIC, "settings.html")

@app.route("/api/settings/reports/generate", methods=["POST"])
def api_generate_report():
    if not current_user():
        return jsonify({"error": "login required"}), 401

    d = request.json or {}
    start_raw = (d.get("start") or "").strip()
    end_raw = (d.get("end") or "").strip()
    service_ids = d.get("service_ids") or []

    if not start_raw or not end_raw:
        return jsonify({"error": "start and end dates required"}), 400

    start_dt = _parse_dt_param(start_raw)
    end_dt = _parse_dt_param(end_raw)
    if not start_dt or not end_dt:
        return jsonify({"error": "invalid date format, use YYYY-MM-DD"}), 400

    end_date = datetime.date.fromisoformat(end_raw) if re.fullmatch(r"\d{4}-\d{2}-\d{2}", end_raw) else end_dt.date()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", end_raw):
        end_dt = end_dt + datetime.timedelta(days=1) - datetime.timedelta(microseconds=1)

    if end_dt < start_dt:
        start_dt, end_dt = end_dt, start_dt
        start_raw, end_raw = end_raw, start_raw
        end_date = datetime.date.fromisoformat(end_raw) if re.fullmatch(r"\d{4}-\d{2}-\d{2}", end_raw) else end_dt.date()

    from_ts = start_dt.timestamp()
    to_ts = end_dt.timestamp()

    ids = []
    for raw in service_ids:
        try:
            ids.append(int(raw))
        except (TypeError, ValueError):
            continue
    if not ids:
        return jsonify({"error": "select at least one service"}), 400

    stats_list = []
    for sid in ids:
        stats = fetch_service_report_stats(sid, from_ts, to_ts, db, DB_LOCK)
        if stats:
            stats_list.append(stats)
    if not stats_list:
        return jsonify({"error": "no valid services found"}), 400

    fd, tmp_path = tempfile.mkstemp(suffix=".pdf")
    os.close(fd)
    try:
        build_report_pdf(stats_list, start_dt.date(), end_date, tmp_path)
        filename = report_filename(start_dt.date(), end_date)
        data_pdf = STATIC.parent / "data" / "weekly_uptime.pdf"
        data_pdf.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(tmp_path, data_pdf)
    except Exception as e:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        log.error("Report PDF generation failed: %s", e)
        return jsonify({"error": "could not generate report"}), 500

    @after_this_request
    def _cleanup(response):
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        return response

    return send_file(tmp_path, mimetype="application/pdf", as_attachment=True, download_name=filename)

# ── Main ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ensure_runtime_started()
    log.info("Uptime Monitor running → http://localhost:%s", PORT)
    app.run(host="0.0.0.0", port=PORT, debug=False, use_reloader=False)
