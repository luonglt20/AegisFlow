# AegisFlow API Reference

`server.py` is a lightweight Python HTTP server (using only the standard library `http.server`) that serves both the Dashboard UI and the backend API. It listens on port `58081`.

## Base URL
```
http://localhost:58081
```

---

## Endpoints

### POST `/api/scan`
Initiates a new security pipeline scan.

**Request:**
- `Content-Type: application/json`
- Body:
```json
{
  "target": "./real-apps/juice-shop",
  "groq_key": "gsk_your_api_key_here",
  "target_url": "http://juice-shop:3000"
}
```

| Field | Type | Required | Description |
|:---|:---|:---|:---|
| `target` | `string` | ✅ Yes | Path to the application to scan, relative to `/app/` inside Docker |
| `groq_key` | `string` | ❌ No | Groq API key for AI Triage. If empty, fallback mode activates |
| `target_url` | `string` | ❌ No | Requested live URL for DAST (Nuclei). The backend only accepts URLs inferred from trusted demo targets or explicitly allowlisted through `AEGIS_ALLOWED_DAST_TARGETS`. |

**Response (Success — 200 OK):**
```json
{
  "status": "SCAN_STARTED"
}
```

**Response (Error — 400 Bad Request):**
```json
{
  "error": "Target URL is not approved for live DAST. Use a server-recognized demo target or configure AEGIS_ALLOWED_DAST_TARGETS."
}
```

**Response (Error — 400 Bad Request):**
```json
{
  "error": "Scan already in progress"
}
```

**Notes:**
- If `target_url` is omitted and the selected target matches a built-in demo mapping such as `juice-shop`, the server derives the live DAST URL automatically.
- If no approved live URL is available, the pipeline falls back to predictive DAST mode.

---

### GET `/api/status`
Returns the real-time status of the currently running or last completed pipeline.

**Response:**
```json
{
  "is_scanning": true,
  "build": "completed",
  "test": "completed",
  "sast": "running",
  "sca": "pending",
  "sbom": "pending",
  "secret": "pending",
  "iac": "pending",
  "dast": "pending",
  "policy": "pending"
}
```

| Stage Value | Meaning |
|:---|:---|
| `"pending"` | Not yet started |
| `"running"` | Currently executing |
| `"completed"` / `"passed"` | Finished successfully |
| `"failed"` | Stage encountered an error |
| `"skipped"` | Stage intentionally skipped (e.g., no target URL for DAST) |

---

### GET `/data/{filename}`
Serves static JSON data files that the Dashboard polls. These are copies of files from `security-results/`, synced by the server after the pipeline completes.

**Available files:**

| Endpoint | File served | Description |
|:---|:---|:---|
| `GET /data/full_report.json` | Normalized vulnerability findings | Raw, pre-AI triage findings |
| `GET /data/full_report_triaged.json` | AI-enriched findings | Dashboard uses this first (preferred) |
| `GET /data/policy_result.json` | Pipeline gate decision | BLOCKED / PASSED / WARNING |
| `GET /data/audit_log.json` | Immutable audit trail | Append-only log array |
| `GET /data/sbom.json` | CycloneDX SBOM | Component inventory |
| `GET /data/build_report.json` | Build stage report | Build pass/fail result |
| `GET /data/test_report.json` | Test stage report | Unit test pass/fail result |

**Notes:**
- Files are served with `Cache-Control: no-cache` to ensure the Dashboard always receives fresh data.
- If a file does not exist yet (e.g., pipeline hasn't reached that stage), the server returns `HTTP 404`.

---

### GET `/`
Serves the Dashboard UI — returns `dashboard/index.html` as the root page.

---

### GET `/{any-other-path}`
Serves static files from the `dashboard/` directory (CSS, JS, etc.).

---

## Dashboard Polling Strategy
The Dashboard does not use WebSockets. It implements long-polling:
1. Every **3 seconds**, `app.js` fires `loadData()`.
2. `loadData()` makes parallel `fetch()` calls to all `/data/*` endpoints.
3. It tries `full_report_triaged.json` first. If that fails (404), it falls back to `full_report.json`.
4. The UI re-renders all components on every successful data refresh.

This makes the dashboard stateless and resilient — it can be refreshed at any time during a scan.
