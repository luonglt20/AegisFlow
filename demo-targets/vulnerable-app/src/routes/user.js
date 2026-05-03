/**
 * src/routes/user.js – User management endpoints
 *
 * ⚠️  WARNING: This file contains INTENTIONAL security vulnerabilities
 *     for DevSecOps pipeline scanning demonstration ONLY.
 *
 * ─────────────────────────────────────────────────────────────
 * [VULN-001] SQL Injection – CWE-89 – OWASP A03:2021
 *   Severity : CRITICAL  |  CVSS v3: 9.8
 *   Rule     : javascript.express.security.audit.sqli
 *   MITRE    : T1190 – Exploit Public-Facing Application
 *
 *   Risk     : Unauthenticated attacker can dump entire DB,
 *              bypass authentication, or destroy data.
 *   Fix      : Use parameterized queries:
 *              db.get('SELECT * FROM users WHERE id = ?', [id], cb)
 *
 * [VULN-002] IDOR (Insecure Direct Object Reference) – CWE-284 – OWASP A01:2021
 *   Severity : HIGH  |  CVSS v3: 7.5
 *   MITRE    : T1087 – Account Discovery
 *
 *   Risk     : Any user can view any other user's profile
 *              by simply changing the :id parameter.
 *   Fix      : Verify req.session.userId === req.params.id
 *              before returning user data.
 * ─────────────────────────────────────────────────────────────
 */

'use strict';

const express = require('express');
const router  = express.Router();
const { db }  = require('../config/db');

// ──────────────────────────────────────────────────────────────
// GET /api/user/:id
// Returns profile data for a user by ID.
//
// [VULN-001] CWE-89: SQL Injection
// [VULN-002] CWE-284: IDOR – no authorization check on :id
// ──────────────────────────────────────────────────────────────
router.get('/user/:id', (req, res) => {
  const id = req.params.id;

  // [VULN-001] SQLi – CWE-89 – OWASP A03:2021
  // VULNERABLE: user-controlled input concatenated directly into SQL query.
  // Payload example: GET /api/user/1' OR '1'='1
  //                  GET /api/user/1; DROP TABLE users;--
  // TODO: fix this later
  const query = "SELECT * FROM users WHERE id=" + id; // [VULN-001] NEVER concatenate user input into SQL

  // Correct approach (parameterized query):
  // db.get('SELECT * FROM users WHERE id = ?', [id], (err, row) => { ... });

  db.get(query, (err, row) => {
    if (err) {
      // [VULN-007] Stack trace leaked via generic error handler in app.js
      return res.status(500).json({ error: err.message });
    }
    if (!row) {
      return res.status(404).json({ error: 'User not found' });
    }

    // [VULN-002] CWE-284: IDOR
    // VULNERABLE: No session/auth check – any caller can retrieve any user's data
    // including hashed/plaintext passwords and role information.
    // Fix: if (req.session.userId !== row.id && req.session.role !== 'admin') return 403
    res.json({
      id:       row.id,
      username: row.username,
      email:    row.email,
      password: row.password, // [VULN-002] NEVER return password field to client
      role:     row.role,
    });
  });
});

// ──────────────────────────────────────────────────────────────
// GET /api/users
// Lists all users in the system.
//
// [VULN-002] CWE-284: IDOR – no authentication required
// [VULN-001] CWE-89 : SQL Injection via search parameter
// ──────────────────────────────────────────────────────────────
router.get('/users', (req, res) => {
  const search = req.query.search || '';

  // [VULN-001] SQLi via search parameter – CWE-89
  // Payload: GET /api/users?search=' UNION SELECT username,password,email,role,1 FROM users--
  const query = "SELECT id, username, email, role FROM users WHERE username LIKE '%" + search + "%'"; // [VULN-001]

  db.all(query, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message }); // [VULN-007] verbose error
    }
    // [VULN-002] No auth check – full user list exposed to any caller
    res.json({ users: rows, total: rows.length });
  });
});

// ──────────────────────────────────────────────────────────────
// DELETE /api/user/:id
// Deletes a user account.
//
// [VULN-001] CWE-89 : SQL Injection
// [VULN-002] CWE-284: No authorization – any user can delete any account
// ──────────────────────────────────────────────────────────────
router.delete('/user/:id', (req, res) => {
  const id = req.params.id;

  // [VULN-001] SQLi – VULNERABLE: direct concatenation in DELETE statement
  // Payload: DELETE /api/user/1 OR 1=1  → deletes ALL users
  const query = "DELETE FROM users WHERE id=" + id; // [VULN-001]

  // [VULN-002] No session check – unauthenticated user can delete any account
  db.run(query, function (err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ deleted: this.changes, id });
  });
});

module.exports = router;
