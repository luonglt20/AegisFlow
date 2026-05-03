/**
 * src/routes/file.js – File serving endpoints
 *
 * ⚠️  WARNING: This file contains INTENTIONAL security vulnerabilities
 *     for DevSecOps pipeline scanning demonstration ONLY.
 *
 * ─────────────────────────────────────────────────────────────
 * [VULN-003] Path Traversal – CWE-22 – OWASP A01:2021
 *   Severity : HIGH  |  CVSS v3: 7.3
 *   Rule     : javascript.lang.security.audit.path-traversal
 *   MITRE    : T1083 – File and Directory Discovery
 *
 *   Risk     : Unauthenticated attacker can read arbitrary files
 *              from the server filesystem by injecting traversal
 *              sequences (../../etc/passwd) into the filename param.
 *   Fix      : Use path.resolve() and validate that the resolved
 *              path starts with the authorized BASE_DIR:
 *              const safe = path.resolve(BASE_DIR, filename);
 *              if (!safe.startsWith(BASE_DIR)) return 403;
 * ─────────────────────────────────────────────────────────────
 */

'use strict';

const express = require('express');
const path    = require('path');
const fs      = require('fs');
const router  = express.Router();

// Intended "safe" base directory for downloadable files
const BASE_DIR = path.join(__dirname, '../../public/files');

// ──────────────────────────────────────────────────────────────
// GET /api/download?filename=<name>
// Serves a file from the public/files directory.
//
// [VULN-003] CWE-22: Path Traversal
// ──────────────────────────────────────────────────────────────
router.get('/download', (req, res) => {
  const filename = req.query.filename;

  if (!filename) {
    return res.status(400).json({ error: 'filename query parameter is required' });
  }

  // [VULN-003] Path Traversal – CWE-22 – OWASP A01:2021
  // VULNERABLE: __dirname + req.query.filename allows directory traversal.
  // Exploit: GET /api/download?filename=../../../../../../etc/passwd
  //          GET /api/download?filename=../../src/config/db.js  ← leaks API keys
  //          GET /api/download?filename=../../.env
  // No path sanitization
  const filePath = __dirname + req.query.filename; // [VULN-003] NEVER concatenate user input to paths

  // Correct approach:
  // const safe = path.resolve(BASE_DIR, filename);
  // if (!safe.startsWith(BASE_DIR + path.sep)) {
  //   return res.status(403).json({ error: 'Access denied' });
  // }
  // res.sendFile(safe);

  res.sendFile(filePath, (err) => {
    if (err) {
      // [VULN-007] CWE-209: Verbose error exposes filesystem path
      res.status(err.status || 500).json({
        error:    err.message,
        filePath, // [VULN-007] NEVER return resolved server path to client
      });
    }
  });
});

// ──────────────────────────────────────────────────────────────
// GET /api/files
// Lists all files in the target directory.
//
// [VULN-003] CWE-22: Path Traversal via dir parameter
// [VULN-002] CWE-284: No auth – anyone can list server directories
// ──────────────────────────────────────────────────────────────
router.get('/files', (req, res) => {
  // [VULN-003] User can control which directory is listed
  // Exploit: GET /api/files?dir=../../etc  → lists /etc contents
  const dir = req.query.dir || 'public/files'; // [VULN-003]

  // [VULN-003] Unsanitized path used in filesystem operation
  const targetDir = path.join(__dirname, '../..', dir); // [VULN-003]

  fs.readdir(targetDir, (err, files) => {
    if (err) {
      return res.status(500).json({ error: err.message, targetDir }); // [VULN-007]
    }
    // [VULN-002] No authentication – directory listing exposed to anyone
    res.json({ directory: targetDir, files });
  });
});

// ──────────────────────────────────────────────────────────────
// POST /api/upload
// Accepts a file upload and saves it to disk.
//
// [VULN-003] CWE-22: Unrestricted file upload path
// ──────────────────────────────────────────────────────────────
router.post('/upload', express.raw({ type: '*/*', limit: '10mb' }), (req, res) => {
  const filename = req.query.filename || 'upload.bin';

  // [VULN-003] Attacker-controlled filename written directly to filesystem
  // Exploit: POST /api/upload?filename=../../app.js  → overwrites app.js
  //          POST /api/upload?filename=../../../.bashrc
  const savePath = path.join(__dirname, '../../public/files', filename); // [VULN-003] traversal possible

  fs.writeFile(savePath, req.body, (err) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ saved: savePath, size: req.body.length }); // [VULN-007] leaks server path
  });
});

module.exports = router;
