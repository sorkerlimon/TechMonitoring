# ══════════════════════════════════════════════════════════════════
#   config.py  —  Edit this file to add/remove services
# ══════════════════════════════════════════════════════════════════

# Database file path (SQLite)
DB_FILE = "uptime_monitor.db"

# Dashboard web port
PORT = 8080

# ── Services ───────────────────────────────────────────────────────
# Add as many as you want.
# interval = how often to check in seconds
#   30  = every 30 seconds
#   60  = every 1 minute
#   300 = every 5 minutes

SERVICES = [
    {
        "name":     "AuthPay UK",
        "url":      "https://authpay.co.uk",
        "interval": 60,         # check every 60 seconds
    },
    {
        "name":     "Google",
        "url":      "https://www.google.com",
        "interval": 30,         # check every 30 seconds
    },
    {
        "name":     "GitHub",
        "url":      "https://github.com",
        "interval": 60,
    },
    {
        "name":     "Cloudflare",
        "url":      "https://www.cloudflare.com",
        "interval": 120,        # check every 2 minutes
    },
    # ── Add more below ─────────────────────────────────────────────
    # {
    #     "name":     "My API",
    #     "url":      "https://api.mysite.com/health",
    #     "interval": 30,
    # },
    # {
    #     "name":     "Staging",
    #     "url":      "https://staging.mysite.com",
    #     "interval": 300,
    # },
]
