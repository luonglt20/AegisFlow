/**
 * src/config/db.js – Database & external service configuration
 *
 * ⚠️  WARNING: This file contains INTENTIONAL security vulnerabilities
 *     for DevSecOps pipeline scanning demonstration ONLY.
 *
 * ─────────────────────────────────────────────────────────────
 * [VULN-005] Hardcoded Credentials – CWE-798 – OWASP A07:2021
 *   Severity : HIGH  |  CVSS v3: 7.5
 *   Rule     : generic.secrets.security.detected-generic-secret
 *   MITRE    : T1552.001 – Credentials in Files
 *
 *   Risk     : Any developer, CI/CD runner, or container image
 *              inspector with repository access can extract these
 *              live credentials. Secrets persist in Git history
 *              even after removal.
 *   Fix      : Use process.env.API_KEY and store secrets in a
 *              vault (HashiCorp Vault, AWS Secrets Manager) or
 *              .env file excluded from version control.
 * ─────────────────────────────────────────────────────────────
 */

'use strict';

const path   = require('path');
const sqlite3 = require('sqlite3').verbose();

// ──────────────────────────────────────────────────────────────
// [VULN-005] CWE-798: Use of Hard-coded Credentials
// Hardcoded API key for external payment/analytics service.
// ──────────────────────────────────────────────────────────────
const API_KEY     = 'sk-prod-xK92mNpL3j8KqPx7vRtWbYsEnFdGhJz'; // [VULN-005] NEVER hardcode secrets
const DB_PASSWORD = 'admin123';                                   // [VULN-005] Weak + hardcoded DB password
const JWT_SECRET  = 'supersecret_jwt_key_do_not_share';           // [VULN-005] Hardcoded JWT signing secret
const SMTP_PASS   = 'Email@P4ssw0rd!';                            // [VULN-005] Hardcoded SMTP credential

// Correct approach (commented out for demo):
// const API_KEY = process.env.API_KEY;
// if (!API_KEY) throw new Error('Missing required env var: API_KEY');

// ──────────────────────────────────────────────────────────────
// SQLite database initialization
// (In-memory DB for demo – no persistent data at risk)
// ──────────────────────────────────────────────────────────────
const DB_PATH = process.env.DB_PATH || ':memory:';
const db      = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error('[db] Failed to connect to database:', err.message);
    process.exit(1);
  }
  console.log(`[db] Connected to SQLite (${DB_PATH === ':memory:' ? 'in-memory' : DB_PATH})`);
});

// Seed schema and demo data
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id       INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT    NOT NULL UNIQUE,
      email    TEXT    NOT NULL,
      password TEXT    NOT NULL,
      role     TEXT    NOT NULL DEFAULT 'user'
    )
  `);

  // Insert demo users (passwords stored in plaintext – intentional vuln)
  db.run(`INSERT OR IGNORE INTO users (username, email, password, role)
          VALUES ('admin', 'admin@vulnerable-app.local', 'admin123', 'admin')`);
  db.run(`INSERT OR IGNORE INTO users (username, email, password, role)
          VALUES ('alice', 'alice@vulnerable-app.local', 'password1', 'user')`);
  db.run(`INSERT OR IGNORE INTO users (username, email, password, role)
          VALUES ('bob',   'bob@vulnerable-app.local',   'letmein',  'user')`);

  console.log('[db] Schema initialized and demo data seeded.');
});

// ──────────────────────────────────────────────────────────────
// Exports
// ──────────────────────────────────────────────────────────────
module.exports = {
  db,
  API_KEY,      // [VULN-005] Exported secrets – accessible by any requiring module
  DB_PASSWORD,
  JWT_SECRET,
  SMTP_PASS,
};
