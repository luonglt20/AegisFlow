# AegisFlow AI Triage Engine

The `pipeline/ai_triage_engine.py` is the most sophisticated and unique component of AegisFlow. It is responsible for elevating raw vulnerability findings into actionable, context-rich intelligence.

## Architecture: Dual-Mode Engine

The engine operates in two modes, selected automatically at runtime:

```
                  ┌───────────────────────────────┐
                  │      ai_triage_engine.py        │
                  │                                 │
  full_report.json│         ┌─────────────┐        │  full_report_triaged.json
  ────────────────►  Filter │ GROQ_API_KEY│        ├──────────────────────────►
                  │  C+H    │  present?   │        │
                  │ only    └──────┬──────┘        │
                  │                │               │
                  │       Yes ─────┤───── No       │
                  │                │               │
                  │    ┌───────────▼────┐  ┌────────────────────────┐
                  │    │  Groq API Mode │  │  Local Rule Engine Mode │
                  │    │  (LLaMA 3.3)   │  │  (Deterministic CVSS)  │
                  │    └───────────┬────┘  └────────────────────────┘
                  └───────────────────────────────────────────────────
```

## Mode 1: Groq API (LLM-Powered)

When `GROQ_API_KEY` is provided, the engine calls the Groq LLaMA 3 API.

### What it does per finding:
1. **Filters** to only CRITICAL and HIGH severity findings (to conserve API calls).
2. **Builds a structured prompt** containing:
   - The vulnerability title and rule ID.
   - The affected file and line number.
   - The raw code snippet from the scanner.
   - The severity and CVSS score.
3. **Calls the Groq API** asking the LLM to return a JSON with:
   - `classification`: `"True Positive"` or `"False Positive"`.
   - `analysis`: A human-readable explanation of the risk.
   - `fix_before`: The vulnerable code.
   - `fix_after`: The secure, corrected code.
   - `explanation`: Why the fix works.

### Throttling & Rate Limit Handling
Groq's free tier enforces strict rate limits. The engine has these safeguards:
- **Max Concurrent Workers:** `3` (reduced from 10 to avoid 429 errors).
- **Per-request delay:** `1.2 seconds` between each API call.
- **Retry Logic:** Up to `5` retries with exponential backoff (`7s` initial wait, doubling each attempt).
- **Automatic Fallback:** If all retries fail, the individual finding is automatically handed to the Local Rule Engine.

### Key Code Location
```
pipeline/ai_triage_engine.py
  call_groq_api()    → Makes the HTTP call to Groq's API
  triage_finding()   → Orchestrates retry logic + fallback per finding
  main()             → ThreadPoolExecutor with max_workers=3
```

## Mode 2: Local Rule Engine (Deterministic Fallback)

Used when `GROQ_API_KEY` is not set, or when Groq API calls fail after all retries.

This is a deterministic, keyword-based rule engine embedded within the script. It uses heuristics to pre-classify findings:

| Rule Trigger | Classification | Reasoning |
|:---|:---|:---|
| `severity == CRITICAL` and `cvss >= 9.0` | True Positive | Statistically, near-certain TP |
| Rule ID contains `sqli` or `injection` | True Positive | High-confidence rule categories |
| `epss_score >= 0.5` | True Positive | High exploit likelihood |
| `severity == LOW` and `epss < 0.01` | False Positive | Low-risk, low-probability = noise |
| Default | True Positive with Medium Confidence | Conservative default |

## Output Fields Added to Each Finding
Both modes write these fields back to the finding object in `full_report_triaged.json`:

```json
{
  "status": "AI_TRIAGED",
  "ai_analysis": "The code directly interpolates user input into an SQL query...",
  "ai_fix": {
    "before": "db.query(`SELECT * FROM users WHERE id = ${req.body.id}`);",
    "after": "db.query('SELECT * FROM users WHERE id = ?', [req.body.id]);",
    "explanation": "Parameterized queries prevent the SQL engine from treating input as code."
  },
  "triage_mode": "groq-llama3"
}
```

## Enabling AI Triage
Set the environment variable before starting the Docker container:
```bash
export GROQ_API_KEY="gsk_your_key_here"
docker-compose up
```
Or pass it directly via the Dashboard UI's "API Key" field before initiating a scan.
