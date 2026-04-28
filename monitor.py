"""
Multi-Service Uptime Monitor
- Add unlimited services in config.py
- SQLite database for all history
- REST API + Web Dashboard
Run: python monitor.py
"""

import ssl, socket, time, json, threading, http.server
import urllib.request, datetime, sqlite3, os
from pathlib import Path
from urllib.parse import urlparse

# ── Import user config ─────────────────────────────────────────────────────────
from config import SERVICES, DB_FILE, PORT

# ── Database setup ─────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS services (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT    NOT NULL,
            url         TEXT    NOT NULL UNIQUE,
            interval    INTEGER NOT NULL DEFAULT 60,
            enabled     INTEGER NOT NULL DEFAULT 1,
            created_at  TEXT    DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS checks (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            service_id  INTEGER NOT NULL REFERENCES services(id),
            checked_at  TEXT    NOT NULL DEFAULT (datetime('now')),
            ts          REAL    NOT NULL,
            is_up       INTEGER NOT NULL,
            response_ms REAL    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS cert_info (
            service_id      INTEGER PRIMARY KEY REFERENCES services(id),
            ssl_expiry      TEXT,
            domain_expiry   TEXT,
            updated_at      TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_checks_service ON checks(service_id);
        CREATE INDEX IF NOT EXISTS idx_checks_ts      ON checks(ts);
    """)
    db.commit()

    # Upsert services from config
    for svc in SERVICES:
        db.execute("""
            INSERT INTO services (name, url, interval, enabled)
            VALUES (?, ?, ?, 1)
            ON CONFLICT(url) DO UPDATE SET
                name     = excluded.name,
                interval = excluded.interval
        """, (svc["name"], svc["url"], svc["interval"]))
    db.commit()
    db.close()
    print(f"[db] Initialized → {DB_FILE}")

DB_LOCK = threading.Lock()

# ── Network helpers ────────────────────────────────────────────────────────────

def check_url(url: str, timeout: int = 10):
    start = time.perf_counter()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "UptimeBot/2.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            r.read()
        ms = (time.perf_counter() - start) * 1000
        return True, round(ms, 2)
    except Exception:
        ms = (time.perf_counter() - start) * 1000
        return False, round(ms, 2)

def get_ssl_expiry(hostname: str):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((hostname, 443), timeout=10),
            server_hostname=hostname
        ) as s:
            cert = s.getpeercert()
            exp = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").date()
            return str(exp)
    except Exception as e:
        print(f"[ssl:{hostname}] {e}")
        return None

def get_domain_expiry(hostname: str):
    try:
        import whois
        w = whois.whois(hostname)
        exp = w.expiration_date
        if isinstance(exp, list): exp = exp[0]
        if isinstance(exp, datetime.datetime): return str(exp.date())
        if isinstance(exp, datetime.date): return str(exp)
        return None
    except Exception as e:
        print(f"[whois:{hostname}] {e}")
        return None

def days_until(date_str):
    if not date_str: return None
    try:
        d = datetime.date.fromisoformat(date_str)
        return (d - datetime.date.today()).days
    except:
        return None

# ── Stats from DB ──────────────────────────────────────────────────────────────

def uptime_pct(service_id: int, hours: int) -> float:
    cutoff = time.time() - hours * 3600
    with DB_LOCK:
        db = get_db()
        row = db.execute("""
            SELECT COUNT(*) total,
                   SUM(CASE WHEN is_up=1 THEN 1 ELSE 0 END) up_count
            FROM checks WHERE service_id=? AND ts>=?
        """, (service_id, cutoff)).fetchone()
        db.close()
    if not row or not row["total"]: return 100.0
    return round(row["up_count"] / row["total"] * 100, 2)

def avg_response(service_id: int, hours: int) -> float:
    cutoff = time.time() - hours * 3600
    with DB_LOCK:
        db = get_db()
        row = db.execute("""
            SELECT AVG(response_ms) avg FROM checks
            WHERE service_id=? AND ts>=? AND is_up=1
        """, (service_id, cutoff)).fetchone()
        db.close()
    if not row or row["avg"] is None: return 0.0
    return round(row["avg"], 2)

def recent_checks(service_id: int, limit: int = 120):
    cutoff = time.time() - 7200
    with DB_LOCK:
        db = get_db()
        rows = db.execute("""
            SELECT ts, is_up, response_ms FROM checks
            WHERE service_id=? AND ts>=?
            ORDER BY ts ASC LIMIT ?
        """, (service_id, cutoff, limit)).fetchall()
        db.close()
    return [{"ts": r["ts"], "ok": bool(r["is_up"]), "ms": r["response_ms"]} for r in rows]

def last_check(service_id: int):
    with DB_LOCK:
        db = get_db()
        row = db.execute("""
            SELECT is_up, response_ms FROM checks
            WHERE service_id=? ORDER BY ts DESC LIMIT 1
        """, (service_id,)).fetchone()
        db.close()
    if not row: return None, None
    return bool(row["is_up"]), row["response_ms"]

def get_cert_info(service_id: int):
    with DB_LOCK:
        db = get_db()
        row = db.execute(
            "SELECT ssl_expiry, domain_expiry FROM cert_info WHERE service_id=?",
            (service_id,)
        ).fetchone()
        db.close()
    if not row: return None, None
    return row["ssl_expiry"], row["domain_expiry"]

def save_cert_info(service_id: int, ssl_exp, domain_exp):
    with DB_LOCK:
        db = get_db()
        db.execute("""
            INSERT INTO cert_info (service_id, ssl_expiry, domain_expiry, updated_at)
            VALUES (?, ?, ?, datetime('now'))
            ON CONFLICT(service_id) DO UPDATE SET
                ssl_expiry    = excluded.ssl_expiry,
                domain_expiry = excluded.domain_expiry,
                updated_at    = excluded.updated_at
        """, (service_id, ssl_exp, domain_exp))
        db.commit()
        db.close()

# ── Monitor threads ────────────────────────────────────────────────────────────

def monitor_service(service_id: int, name: str, url: str, interval: int):
    hostname = urlparse(url).hostname
    print(f"[{name}] Starting monitor → {url} every {interval}s")

    # Cert info on startup
    ssl_exp    = get_ssl_expiry(hostname)
    domain_exp = get_domain_expiry(hostname)
    save_cert_info(service_id, ssl_exp, domain_exp)
    last_cert_refresh = time.time()

    while True:
        is_up, ms = check_url(url)
        ts = time.time()

        with DB_LOCK:
            db = get_db()
            db.execute("""
                INSERT INTO checks (service_id, ts, is_up, response_ms)
                VALUES (?, ?, ?, ?)
            """, (service_id, ts, 1 if is_up else 0, ms))
            db.commit()
            db.close()

        status = "UP  " if is_up else "DOWN"
        print(f"[{name}] {status} {ms:7.1f}ms")

        # Refresh certs every 6 hours
        if time.time() - last_cert_refresh > 21600:
            ssl_exp    = get_ssl_expiry(hostname)
            domain_exp = get_domain_expiry(hostname)
            save_cert_info(service_id, ssl_exp, domain_exp)
            last_cert_refresh = time.time()

        time.sleep(interval)

def start_monitors():
    with DB_LOCK:
        db = get_db()
        services = db.execute(
            "SELECT id, name, url, interval FROM services WHERE enabled=1"
        ).fetchall()
        db.close()

    for svc in services:
        t = threading.Thread(
            target=monitor_service,
            args=(svc["id"], svc["name"], svc["url"], svc["interval"]),
            daemon=True
        )
        t.start()

# ── API builder ────────────────────────────────────────────────────────────────

def build_dashboard_data():
    with DB_LOCK:
        db = get_db()
        services = db.execute(
            "SELECT id, name, url, interval FROM services WHERE enabled=1"
        ).fetchall()
        db.close()

    result = []
    for svc in services:
        sid = svc["id"]
        is_up, cur_ms = last_check(sid)
        ssl_exp, dom_exp = get_cert_info(sid)
        result.append({
            "id":           sid,
            "name":         svc["name"],
            "url":          svc["url"],
            "interval":     svc["interval"],
            "current_up":   is_up,
            "current_ms":   cur_ms or 0,
            "avg_ms_24h":   avg_response(sid, 24),
            "uptime_24h":   uptime_pct(sid, 24),
            "uptime_30d":   uptime_pct(sid, 24 * 30),
            "uptime_1y":    uptime_pct(sid, 24 * 365),
            "ssl_expiry":   ssl_exp,
            "ssl_days":     days_until(ssl_exp),
            "domain_expiry":dom_exp,
            "domain_days":  days_until(dom_exp),
            "history":      recent_checks(sid),
        })
    return result

# ── HTTP server ────────────────────────────────────────────────────────────────

DASHBOARD_HTML = Path(__file__).parent / "dashboard.html"

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_GET(self):
        if self.path == "/api/services":
            body = json.dumps(build_dashboard_data()).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)

        elif self.path == "/api/db-stats":
            with DB_LOCK:
                db = get_db()
                total = db.execute("SELECT COUNT(*) c FROM checks").fetchone()["c"]
                db.close()
            body = json.dumps({"total_checks": total, "db_file": DB_FILE}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)

        elif self.path in ("/", "/index.html"):
            if DASHBOARD_HTML.exists():
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(DASHBOARD_HTML.read_bytes())
            else:
                self.send_response(404); self.end_headers()
        else:
            self.send_response(404); self.end_headers()

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    init_db()
    start_monitors()

    server = http.server.HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"\n  Multi-Service Uptime Monitor")
    print(f"  Services   : {len(SERVICES)}")
    print(f"  Database   : {DB_FILE}")
    print(f"  Dashboard  : http://localhost:{PORT}")
    print(f"  API        : http://localhost:{PORT}/api/services\n")
    server.serve_forever()

if __name__ == "__main__":
    main()
