## Tech Monitoring

Lightweight uptime & latency monitoring with a built-in dashboard and REST API.

### Features

- **Multi-service monitors**: HTTP(S) checks with interval, retries, timeout, method
- **Dashboard**: overview + per-service detail page
- **History**: stored in SQLite (`DB_FILE`)
- **Auth**: session login for UI + API Keys for programmatic access

### Run (Docker)

From `TechMonitoring/`:

```bash
docker compose up --build
```

Open:

- **Dashboard**: `http://127.0.0.1:3001`

### Run (Local Python)

```bash
python -m venv .venv
source .venv/bin/activate  # (Windows: .venv\Scripts\activate)
pip install -r requirements.txt
python app.py
```

### Configuration

- **DB location**: set `DB_FILE` (default: `uptime.db`)
- **Secret key**: set `UPTIME_SECRET_KEY` (required for production)

### API Documentation

See `docs/API.md`.

