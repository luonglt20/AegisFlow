/**
 * app.js – Main entry point for vulnerable-app
 *
 * ??  WARNING: This application contains INTENTIONAL security vulnerabilities
 *     created solely for DevSecOps pipeline scanning demonstration.
 *     DO NOT deploy to any production, staging, or internet-facing environment.
 *
 * Vulnerabilities present in this app:
 *   [VULN-001] SQLi      – CWE-89  – OWASP A03:2021  ? src/routes/user.js
 *   [VULN-002] IDOR      – CWE-284 – OWASP A01:2021  ? src/routes/user.js
 *   [VULN-003] Path Trav – CWE-22  – OWASP A01:2021  ? src/routes/file.js
 *   [VULN-004] XSS       – CWE-79  – OWASP A03:2021  ? src/routes/auth.js
 *   [VULN-005] Secret    – CWE-798 – OWASP A07:2021  ? src/config/db.js
 *   [VULN-006] RootCont  – CWE-250 – OWASP A05:2021  ? Dockerfile
 */

'use strict';

const express = require('express');
const path    = require('path');

// --------------------------------------------------------------
// App Initialization
// --------------------------------------------------------------
const app  = express();
const PORT = process.env.PORT || 53000;

// --------------------------------------------------------------
// Middleware
// --------------------------------------------------------------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// [VULN-MISSING-HEADERS] No security headers (helmet not used)
// Missing: X-Frame-Options, Content-Security-Policy, HSTS, etc.
// Remediation: app.use(require('helmet')())

// --------------------------------------------------------------
// Routes
// --------------------------------------------------------------
const userRoutes = require('./src/routes/user');
const fileRoutes = require('./src/routes/file');
const authRoutes = require('./src/routes/auth');

app.use('/api', userRoutes);
app.use('/api', fileRoutes);
app.use('/api', authRoutes);

// --------------------------------------------------------------
// Root endpoint
// --------------------------------------------------------------
app.get('/', (req, res) => {
  res.json({
    app:     'vulnerable-app',
    version: '1.0.0',
    warning: '??  This app contains intentional vulnerabilities for demo purposes only.',
    endpoints: {
      user:     'GET /api/user/:id',
      download: 'GET /api/download?filename=<name>',
      search:   'GET /api/search?q=<query>',
      login:    'POST /api/login',
    },
  });
});

// --------------------------------------------------------------
// [VULN-007] Verbose Error Handler – CWE-209 – OWASP A05:2021
// Exposes full stack traces to the client in all environments.
// Remediation: return generic message in production, log internally.
// --------------------------------------------------------------
app.use((err, req, res, next) => {
  // [VULN-007] CWE-209: Information Exposure Through an Error Message
  console.error(err);
  res.status(500).json({
    error: err.message,   // VULNERABLE: leaks internal error message
    stack: err.stack,     // VULNERABLE: leaks full stack trace to client
  });
});

// --------------------------------------------------------------
// Start server
// --------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`[vulnerable-app] Server running on http://localhost:${PORT}`);
  console.log('[vulnerable-app] ??  DEMO ONLY – Contains intentional vulnerabilities');
});

module.exports = app;
