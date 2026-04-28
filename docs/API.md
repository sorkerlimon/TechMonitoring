## Tech Monitoring API

Base URL (Docker default): `http://127.0.0.1:3001`

### Quickstart (curl)

Set your API key once:

```bash
export API_KEY="YOUR_API_KEY"
export BASE="http://127.0.0.1:3001"
```

Then call endpoints with an API key header:

```bash
curl -sS -H "X-API-Key: $API_KEY" "$BASE/api/services"
```

### Authentication

There are two auth modes:

- **Browser UI**: session cookie after `/login`
- **API Keys**: pass the key as:
  - Header: `X-API-Key: <key>`
  - or `Authorization: Bearer <key>`
  - or query string: `?api_key=<key>`

If auth is required and missing, endpoints return **401**.

### Common query parameters

#### Date range

Supported params:

- `start` / `end` (preferred)
- `from` / `to` (aliases)

Formats:

- `YYYY-MM-DD`
- `YYYY-MM-DDTHH:MM`
- `YYYY-MM-DDTHH:MM:SS` (or space instead of `T`)

Notes:

- If `end` is a **date only**, it is treated as **end-of-day**.
- If only one side is provided:
  - missing `start` ⇒ from the beginning (`0.0`)
  - missing `end` ⇒ now
- If `end < start`, they are swapped.

#### Ordering

- `order_by`: `ts`, `datetime`, `checked_at`, `response_ms`, `status_code`, `is_up`, `id`
- `order_direction`: `ASC` or `DESC`

#### Pagination

Common pagination params:

- `page`: 1-based (default `1`)
- `page_size`: (default varies by endpoint; max enforced server-side)

### Endpoints

#### GET `/api/auth/status`

Returns whether the UI session is logged in.

#### POST `/api/auth/login`

JSON body:

```json
{ "username": "admin", "password": "..." }
```

Example:

```bash
curl -sS -X POST "$BASE/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"YOUR_PASSWORD"}'
```

#### POST `/api/auth/logout`

Ends UI session.

Example:

```bash
curl -sS -X POST "$BASE/api/auth/logout"
```

#### GET `/api/services`

Lists all services (for UI).

Example:

```bash
curl -sS -H "X-API-Key: $API_KEY" "$BASE/api/services"
```

#### GET `/api/services/<sid>`

Service detail (for UI).

Example:

```bash
curl -sS -H "X-API-Key: $API_KEY" "$BASE/api/services/1"
```

#### GET `/api/services/<sid>/checks`

Paginated checks for a service.

Query params:

- `range`: e.g. `2h`, `1d` (default `2h`) — used when `start/end` not provided
- `start`, `end`: date range (optional)
- `page`: default `1`
- `page_size`: default `50` (max `500`)
- `order_by`, `order_direction`: only applied for `start/end` range queries

Examples:

- Last 2 hours (default range):

```bash
curl -sS -H "X-API-Key: $API_KEY" \
  "$BASE/api/services/1/checks?range=2h&page=1&page_size=50"
```

- Date range (and order by datetime desc):

```bash
curl -sS -H "X-API-Key: $API_KEY" \
  "$BASE/api/services/1/checks?start=2026-03-01&end=2026-03-07&order_by=datetime&order_direction=DESC&page=1&page_size=100"
```

#### GET `/api/services/by-name/<friendly_name>`

Returns stats + history for a service looked up by its name.

Query params:

- `range`: e.g. `1h` (default `1h`) — used when `start/end` not provided
- `start`, `end`: date range (optional)
- `history_limit`: hard cap on returned records (default `2000`)
- `page`, `page_size`: when using `start/end`, history becomes paginated
- `order_by`, `order_direction`: when using `start/end`, controls history ordering

When paginated, `history` is an object:

```json
{
  "items": [],
  "total": 0,
  "page": 1,
  "page_size": 200,
  "total_pages": 1,
  "from_ts": 0,
  "to_ts": 0,
  "order_by": "ts",
  "order_direction": "ASC"
}
```

Examples:

- Last 1 hour (default):

```bash
curl -sS -H "X-API-Key: $API_KEY" \
  "$BASE/api/services/by-name/auth?range=1h"
```

- Date range + history pagination + order:

```bash
curl -sS -H "X-API-Key: $API_KEY" \
  "$BASE/api/services/by-name/auth?start=2026-03-01&end=2026-03-07&page=1&page_size=50&order_by=datetime&order_direction=ASC"
```

---

### Write operations (POST/PUT/DELETE)

These endpoints require auth (UI session or API key).

#### POST `/api/services`

Create a monitor.

Body:

```json
{
  "name": "AuthPay UK",
  "url": "https://authpay.co.uk",
  "interval": 60,
  "retries": 0,
  "timeout": 30,
  "method": "GET"
}
```

Example:

```bash
curl -sS -X POST "$BASE/api/services" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"AuthPay UK","url":"https://authpay.co.uk","interval":60,"retries":0,"timeout":30,"method":"GET"}'
```

#### PUT `/api/services/<sid>`

Update a monitor.

Example:

```bash
curl -sS -X PUT "$BASE/api/services/1" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"AuthPay UK","url":"https://authpay.co.uk","interval":30,"retries":1,"timeout":15,"method":"GET"}'
```

#### DELETE `/api/services/<sid>`

Delete a monitor.

Example:

```bash
curl -sS -X DELETE "$BASE/api/services/1" -H "X-API-Key: $API_KEY"
```

#### POST `/api/services/<sid>/pause`

Pause or resume a monitor.

Example:

```bash
curl -sS -X POST "$BASE/api/services/1/pause" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"paused": true}'
```

#### API keys management

These endpoints are typically used from the UI, but can be called via API key/session too.

- `GET /api/settings/api-keys`
- `POST /api/settings/api-keys` with body: `{ "name": "Postman" }`


