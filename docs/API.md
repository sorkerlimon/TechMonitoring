## Tech Monitoring API

Base URL (Docker default): `http://127.0.0.1:3001`

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

### Endpoints

#### GET `/api/auth/status`

Returns whether the UI session is logged in.

#### POST `/api/auth/login`

JSON body:

```json
{ "username": "admin", "password": "..." }
```

#### POST `/api/auth/logout`

Ends UI session.

#### GET `/api/services`

Lists all services (for UI).

#### GET `/api/services/<sid>`

Service detail (for UI).

#### GET `/api/services/<sid>/checks`

Paginated checks for a service.

Query params:

- `range`: e.g. `2h`, `1d` (default `2h`) — used when `start/end` not provided
- `start`, `end`: date range (optional)
- `page`: default `1`
- `page_size`: default `50` (max `500`)
- `order_by`, `order_direction`: only applied for `start/end` range queries

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

