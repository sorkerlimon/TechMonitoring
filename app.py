"""
Uptime Monitor - Flask Backend
Run: python app.py
Dashboard: http://localhost:8080
"""

import ssl, socket, time, json, threading, datetime, sqlite3, os, re, secrets, hashlib, hmac
import urllib.request
from pathlib import Path
from urllib.parse import urlparse
from flask import Flask, request, jsonify, send_from_directory, session, redirect

# ── Config ─────────────────────────────────────────────────────────────────────
DB_FILE  = os.environ.get("DB_FILE", "uptime.db")
PORT     = 8080
STATIC   = Path(__file__).parent / "static"
STATIC.mkdir(exist_ok=True)

app      = Flask(__name__, static_folder=str(STATIC))
app.secret_key = os.environ.get("UPTIME_SECRET_KEY", "dev-secret-change-this")
app.permanent_session_lifetime = datetime.timedelta(hours=1)
app.config["SESSION_REFRESH_EACH_REQUEST"] = False
DB_LOCK  = threading.Lock()
THREADS  = {}   # service_id → thread stop_event
BOOT_LOCK = threading.Lock()
BOOTSTRAPPED = False

# ── DB ─────────────────────────────────────────────────────────────────────────

def db():
    c = sqlite3.connect(DB_FILE, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    with DB_LOCK:
        c = db()
        c.executescript("""
            CREATE TABLE IF NOT EXISTS services (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT    NOT NULL,
                url         TEXT    NOT NULL UNIQUE,
                interval    INTEGER NOT NULL DEFAULT 60,
                retries     INTEGER NOT NULL DEFAULT 0,
                timeout     INTEGER NOT NULL DEFAULT 30,
                method      TEXT    NOT NULL DEFAULT 'GET',
                enabled     INTEGER NOT NULL DEFAULT 1,
                paused      INTEGER NOT NULL DEFAULT 0,
                created_at  TEXT    DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS checks (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                service_id  INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
                ts          REAL    NOT NULL,
                is_up       INTEGER NOT NULL,
                response_ms REAL    NOT NULL,
                status_code INTEGER
            );
            CREATE TABLE IF NOT EXISTS cert_info (
                service_id    INTEGER PRIMARY KEY REFERENCES services(id) ON DELETE CASCADE,
                ssl_expiry    TEXT,
                domain_expiry TEXT,
                updated_at    TEXT
            );
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                is_admin      INTEGER NOT NULL DEFAULT 0,
                created_at    TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS api_keys (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                name          TEXT NOT NULL,
                key_hash      TEXT NOT NULL UNIQUE,
                key_prefix    TEXT NOT NULL,
                active        INTEGER NOT NULL DEFAULT 1,
                created_by    INTEGER REFERENCES users(id) ON DELETE SET NULL,
                created_at    TEXT DEFAULT (datetime('now')),
                last_used_at  TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_checks_svc ON checks(service_id, ts);
            CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
        """)
        c.commit(); c.close()
    print(f"[db] Ready → {DB_FILE}")

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
        start_all()
        BOOTSTRAPPED = True

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
        print(f"[WHOIS:{hostname}] {e}")
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

def range_to_seconds(range_key):
    key = normalize_range_key(range_key, default="2h")
    m = re.fullmatch(r"(\d+)([hd])", key)
    if not m:
        return 2 * 3600
    n = int(m.group(1))
    unit = m.group(2)
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
    # 2hr, 2hrs, 2hour, 2hours -> 2h
    # 1day, 3days -> 1d / 3d
    key = re.sub(r"hours?$", "h", key)
    key = re.sub(r"hrs?$", "h", key)
    key = re.sub(r"days?$", "d", key)

    m = re.fullmatch(r"(\d+)([hd])", key)
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
    hostname = urlparse(url).hostname
    ssl_e  = get_ssl_expiry(hostname)
    dom_e  = get_domain_expiry(hostname)
    save_cert(sid, ssl_e, dom_e)
    last_cert = time.time()
    fail_count = 0

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

        print(f"  [{name}] {'UP  ' if is_up else 'DOWN'} {ms:7.1f}ms {code or ''}")

        if time.time() - last_cert > 21600:
            save_cert(sid, get_ssl_expiry(hostname), get_domain_expiry(hostname))
            last_cert = time.time()

        stop_evt.wait(interval)

def start_service(sid):
    with DB_LOCK:
        c = db()
        r = c.execute("SELECT * FROM services WHERE id=? AND enabled=1 AND paused=0",
                      (sid,)).fetchone()
        c.close()
    if not r: return
    if sid in THREADS:
        THREADS[sid].set()
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

@app.route("/api/services", methods=["GET"])
def api_list():
    return jsonify(build_service())

@app.route("/api/services/<int:sid>", methods=["GET"])
def api_detail(sid):
    data = build_service(sid)
    if not data: return jsonify({"error": "not found"}), 404
    return jsonify(data)

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
        start_service(sid)
        return jsonify({"ok": True, "id": sid})
    except sqlite3.IntegrityError:
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
    stop_service(sid)
    start_service(sid)
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

# ── Main ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ensure_runtime_started()
    print(f"\n  Uptime Monitor running → http://localhost:{PORT}\n")
    app.run(host="0.0.0.0", port=PORT, debug=False, use_reloader=False)
