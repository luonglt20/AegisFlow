/* =========================================================================
   AegisFlow - Enterprise Security Hub Application Logic
   ========================================================================= */

// ─── Constants & Configurations ───────────────────────────────
const SEV_COLORS = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#f59e0b', LOW: '#10b981' };
const TOOL_COLORS = { SAST: '#8b5cf6', SCA: '#06b6d4', IaC: '#f59e0b', DAST: '#10b981', SECRET: '#ec4899' };

// ─── Fallback Lab Data (Mock Data) ────────────────────────────
const mockDataLab = {
  scan_metadata: {
    app_name: "vulnerable-app", version: "v1.0", pipeline_id: "gitlab-pipeline-#4721",
    score: 28, grade: "D", status: "BLOCKED"
  },
  findings: [
    {
      id: "FIND-001", source_tool: "Semgrep", scan_type: "SAST", rule_id: "sqli",
      title: "SQL Injection via req.params.id", severity: "CRITICAL", cvss_v3: 9.8,
      cve_cwe: "CWE-89", owasp_2021: "A03:2021",
      mitre_attack: { tactic: "Initial Access", tactic_id: "TA0001", technique: "Exploit Public-Facing App", technique_id: "T1190" },
      affected_file: "src/routes/user.js", affected_line: 42,
      business_impact: "Full database exfiltration.",
      real_exploit_scenario: "GET /api/user/1' OR '1'='1'; DROP TABLE users;--",
      status: "PENDING_TRIAGE",
      ai_analysis: "[True Positive] Classic SQL injection. Active reachable route.",
      ai_fix: { before: 'query = "SELECT * FROM users WHERE id=" + req.params.id;', after: "db.get('SELECT * FROM users WHERE id = ?', [req.params.id]);", explanation: "Parameterized queries prevent SQLi." },
      ai_confidence: 96, sla_hours: 24, sla_deadline: "2026-05-20T08:00:00Z"
    },
    {
      id: "FIND-002", source_tool: "Trivy", scan_type: "SCA", rule_id: "CVE-2021-44228",
      title: "Log4Shell – RCE in log4j-core 2.14.1", severity: "CRITICAL", cvss_v3: 10.0,
      cve_cwe: "CVE-2021-44228", owasp_2021: "A06:2021",
      mitre_attack: { tactic: "Execution", tactic_id: "TA0002", technique: "Command Interpreter", technique_id: "T1059" },
      affected_package: "log4j-core",
      business_impact: "Full Remote Code Execution.",
      status: "PENDING_TRIAGE",
      ai_analysis: "[True Positive] Log4j-core 2.14.1 is extremely vulnerable.",
      ai_fix: { before: '"log4j-core": "2.14.1"', after: '"log4j-core": "2.17.1"', explanation: "Upgrade to patches release." },
      ai_confidence: 98, sla_hours: 24, sla_deadline: "2026-05-20T08:00:00Z"
    },
    {
      id: "FIND-003", source_tool: "Checkov", scan_type: "IaC", rule_id: "CKV_DOCKER_2",
      title: "Container Running as Root", severity: "CRITICAL", cvss_v3: 8.8,
      cve_cwe: "CWE-250", owasp_2021: "A05:2021",
      mitre_attack: { tactic: "Privilege Escalation", tactic_id: "TA0004", technique: "Escape to Host", technique_id: "T1611" },
      affected_file: "Dockerfile",
      status: "PENDING_TRIAGE",
      ai_analysis: "[True Positive] No USER instruction confirmed.",
      ai_fix: { before: "FROM node:18", after: "FROM node:18\nUSER app", explanation: "Run as non-root user." },
      ai_confidence: 95, sla_hours: 24, sla_deadline: "2026-05-20T08:00:00Z"
    },
    {
      id: "FIND-004", source_tool: "Semgrep", scan_type: "SAST", title: "Hardcoded API Secret", severity: "HIGH", cvss_v3: 7.5, cve_cwe: "CWE-798", owasp_2021: "A07:2021", mitre_attack: { tactic: "Credential Access", tactic_id: "TA0006", technique: "Credentials in Files", technique_id: "T1552" }, status: "PENDING_TRIAGE", ai_analysis: "[True Positive] High-entropy string found.", ai_confidence: 99
    },
    {
      id: "FIND-005", source_tool: "ZAP", scan_type: "DAST", title: "Reflected XSS", severity: "MEDIUM", cvss_v3: 5.3, cve_cwe: "CWE-79", owasp_2021: "A03:2021", mitre_attack: { tactic: "Execution", tactic_id: "TA0002", technique: "Command Interpreter", technique_id: "T1059" }, status: "PENDING_TRIAGE", ai_analysis: "[Needs Review] XSS detected via DAST payload.", ai_confidence: 72
    }
  ]
};

// ─── Application State ─────────────────────────────────────────
const appState = {
  currentTab: 'executive',
  data: { findings: [], scan_metadata: {} },
  auditLog: [
    { ts: "2026-05-19 08:00:00", actor: "Pipeline", action: "SCAN_COMPLETE", finding: "ALL", detail: "Scans completed." },
    { ts: "2026-05-19 08:00:18", actor: "AI Engine", action: "TRIAGE_COMPLETE", finding: "ALL", detail: "AI analysis finished." },
    { ts: "2026-05-19 08:00:20", actor: "System", action: "DASHBOARD_OPENED", finding: "—", detail: "AegisFlow initialized." }
  ],
  filters: { severity: 'all' },
  exceptions: [],
  selectedFinding: null,
  pendingActionId: null,
  excCounter: 1
};

// ─── Hybrid Bridge Data Loader ─────────────────────────────────
let lastDataHash = '';

async function loadData(isPolling = false) {
  try {
    // 1. Fetch Findings
    const res = await fetch('./data/full_report_triaged.json');
    if (!res.ok) throw new Error('Findings unreachable');
    const prodData = await res.json();
    appState.data.findings = prodData.findings || [];
    appState.data.scan_metadata = prodData.scan_metadata || {};

    // 2. Fetch Policy & Compliance Results
    try {
      const polRes = await fetch('./data/policy_result.json');
      if (polRes.ok) {
        appState.policy = await polRes.json();
      }
    } catch (e) { console.warn("Policy data not found."); }

    // 3. Fetch Real Audit Logs
    try {
      const auditRes = await fetch('./data/audit_log.json');
      if (auditRes.ok) {
        const realLogs = await auditRes.json();
        // Convert array of objects to dashboard format if needed
        appState.auditLog = realLogs.map(l => ({
          ts: l.timestamp.replace('T', ' ').substring(0, 19),
          actor: l.actor || 'System',
          action: l.action || 'EVENT',
          finding: l.pipeline_id || '—',
          detail: l.status || 'Success'
        }));
      }
    } catch (e) { console.warn("Audit log file not found."); }

    // Update global UI elements
    const projEl = document.getElementById('project-name');
    const metaEl = document.getElementById('scan-meta');
    if (projEl) projEl.textContent = `Project: ${appState.data.scan_metadata.app_name || 'AegisFlow'}`;
    if (metaEl) metaEl.textContent = `Scan ID: ${appState.data.scan_metadata.pipeline_run_id || 'manual-scan'} · Mode: Penta-Core Live`;

    if (!isPolling) console.log("🟢 PROD Mode: Loaded all live data from pipeline.");
  } catch (err) {
    if (isPolling) return;
    console.warn("🟡 LAB Mode: Fetch failed, using embedded mock data.");
    appState.data.findings = [...mockDataLab.findings];
    appState.data.scan_metadata = { ...mockDataLab.scan_metadata };
  }

  // Refresh KPIs
  const kpiPending = document.getElementById('kpi-pending');
  if (kpiPending) kpiPending.textContent = appState.data.findings.filter(f => f.status === 'PENDING_TRIAGE').length;

  const scoreH2 = document.getElementById('score-value');
  const gradeBadge = document.getElementById('grade-badge');

  if (scoreH2) {
    const score = appState.data.scan_metadata.score || (appState.policy ? (appState.policy.status === 'BLOCKED' ? 25 : 85) : 0);
    scoreH2.innerHTML = `${score}<span style="font-size: 16px; color: var(--text-muted);">/100</span>`;
    scoreH2.style.color = score < 40 ? 'var(--sev-critical)' : (score < 70 ? 'var(--sev-high)' : 'var(--sev-low)');
  }

  if (gradeBadge) {
    const grade = appState.data.scan_metadata.grade || (appState.policy ? (appState.policy.status === 'BLOCKED' ? 'F' : 'A') : 'F');
    gradeBadge.textContent = `GRADE ${grade}`;
    gradeBadge.className = `badge badge-${grade.toLowerCase()}`;
  }

  // Refresh views
  renderFindings();
  initCharts();
  renderAIList();
  renderDevPortal();
  if (!isPolling) renderAuditLog();
  renderOverride();
  renderCompliance();

  if (isPolling && !isPolling.quiet) {
    // quiet poll or just log
  }
}

window.addEventListener('DOMContentLoaded', () => {
  loadData();
  setInterval(() => loadData(true), 5000); // 5 seconds polling
});

// ─── View Controller (Tabs) ────────────────────────────────────
function switchTab(tabId) {
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

  const panel = document.getElementById('tab-' + tabId);
  const nav = document.getElementById('nav-' + tabId);

  if (panel) panel.classList.add('active');
  if (nav) nav.classList.add('active');

  appState.currentTab = tabId;

  if (tabId === 'executive') initCharts();
  if (tabId === 'action') renderFindings();
  if (tabId === 'ai') renderAIList();
  if (tabId === 'override') renderOverride();
  if (tabId === 'engineering') renderEngineering();
  if (tabId === 'universe') console.log('AppSec Universe Activated');
  if (tabId === 'dev') renderDevPortal();
  if (tabId === 'engineering') renderEngineering();
  if (tabId === 'compliance') renderCompliance();
  if (tabId === 'maturity') renderMaturity();
  if (tabId === 'audit') renderAuditLog();
  if (tabId === 'override') renderOverride();
}

function renderEngineering() {
  const findings = appState.data.findings;

  // Calculate KPIs
  const mttdEl = document.getElementById('kpi-mttd');
  const mttrEl = document.getElementById('kpi-mttr');
  const verEl = document.getElementById('kpi-ver');
  const gateEl = document.getElementById('kpi-gate');

  if (mttdEl) mttdEl.innerText = "12.4h"; // Simulate MTTD
  if (mttrEl) {
     const criticals = findings.filter(f => f.severity === 'CRITICAL');
     mttrEl.innerText = criticals.length > 0 ? "Blocked" : "SLA 15d";
  }
  if (verEl) verEl.innerText = "2.8%"; // Simulate Escape Rate
  if (gateEl) {
    const isBlocked = appState.policy && appState.policy.status === 'BLOCKED';
    gateEl.innerText = isBlocked ? "FAIL" : "PASS";
    gateEl.style.color = isBlocked ? 'var(--sev-critical)' : 'var(--sev-low)';
  }
}

// ─── UI Helpers ────────────────────────────────────────────────
function esc(str) { return String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

function getBadge(text, cls) {
  return `<span class="badge ${cls}">${text}</span>`;
}

function getSevBadge(sev) {
  const map = { CRITICAL: 'badge-critical', HIGH: 'badge-high', MEDIUM: 'badge-medium', LOW: 'badge-low' };
  return getBadge(sev, map[sev]);
}

// ─── Action Center ─────────────────────────────────────────────
function setFilter(key, val, btnEl) {
  Array.from(btnEl.parentNode.children).forEach(b => b.classList.remove('active'));
  btnEl.classList.add('active');
  appState.filters[key] = val;
  renderFindings();
}

function renderFindings() {
  const list = document.getElementById('findings-list');
  const countSpan = document.getElementById('action-counts');

  const filtered = appState.data.findings.filter(f => {
    if (appState.filters.severity !== 'all' && f.severity !== appState.filters.severity) return false;
    return true;
  });

  if (countSpan) countSpan.textContent = `Showing ${filtered.length} of ${appState.data.findings.length} findings`;

  if (filtered.length === 0) {
    list.innerHTML = `<div class="card" style="text-align: center;"><p style="color:var(--text-muted)">No findings match the filters.</p></div>`;
    return;
  }

  list.innerHTML = filtered.map(f => {
    const sevClass = f.severity.toLowerCase();
    const hasAI = f.ai_analysis && f.ai_fix;
    const slaText = f.sla_desc || (f.severity === 'CRITICAL' ? '24 hours' : '7 days');

    return `
      <div class="finding-item ${sevClass}">
        <div class="finding-header" onclick="toggleBody('fb-${f.id}')">
          <div style="grid-column: 1 / 3;">
            <div style="display: flex; gap: 8px; margin-bottom: 6px;">
              ${getSevBadge(f.severity)}
              ${getBadge(f.scan_type, 'badge-outline')}
              ${getBadge(f.status.replace('_', ' '), 'badge-brand')}
              ${getBadge('SLA: ' + slaText, 'badge-outline')}
            </div>
            <div class="finding-title">${f.title}</div>
            <div class="finding-subtitle font-mono">${f.affected_file || f.affected_package || f.affected_url || f.id}</div>
            <div style="font-size: 11px; color: var(--brand-primary); margin-top: 4px; font-weight: 600;">
               OWASP Mapping: ${f.owasp_mapping || f.owasp_2021 || 'N/A'}
            </div>
          </div>
          <div style="text-align: right;">
             <div style="font-size: 13px; font-weight: 700; color: ${SEV_COLORS[f.severity]}">CVSS ${f.cvss_v3 || '-'}</div>
             <div class="font-mono" style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">${f.id}</div>
          </div>
        </div>

        <div class="finding-body" id="fb-${f.id}">
          <div style="margin-bottom: 16px;">
            <div style="background: rgba(0,0,0,0.2); padding: 12px; border-radius: 8px; margin-bottom: 12px; border-left: 3px solid var(--brand-primary);">
                <h4 style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); margin-bottom: 4px;">Compliance Remediation Control</h4>
                <p style="font-size: 13px; color: var(--text-main);">${f.compliance_controls || "N/A"}</p>
            </div>

            <p style="font-size: 13px; color: var(--text-main); margin-bottom: 8px;"><strong>Impact:</strong> ${f.business_impact || "🔍 Waiting for AI deep context analysis..."}</p>

            ${f.code_context ? `
            <div class="code-container">
               <div class="code-container-header" style="color: var(--brand-primary); font-size: 11px;">CODE CONTEXT (Line ${f.affected_line})</div>
               <pre class="code-block" style="font-size: 11px;">${esc(f.code_context)}</pre>
            </div>
            ` : ''}

            <div style="font-size: 11px; color: var(--text-muted); margin: 12px 0 8px 0;">
                <strong>STRIDE:</strong> ${f.stride_category || 'N/A'} |
                <strong>Framework:</strong> ${f.owasp_mapping || 'Other'}
            </div>

            ${f.scan_type === 'SAST' ? `<div style="font-size: 12px; background: rgba(0, 188, 212, 0.05); padding: 8px; border-radius: 4px; border-left: 2px solid #00BCD4; margin-bottom: 10px;"><strong>Taint Analysis:</strong> Source (User Input) → Propagation → Sink (Vulnerable Function)</div>` : ''}
            ${f.scan_type === 'SECRET' ? `<div style="font-size: 12px; background: rgba(255, 107, 0, 0.05); padding: 8px; border-radius: 4px; border-left: 2px solid var(--brand-primary); margin-bottom: 10px;"><strong>Entropy:</strong> High-entropy string detected (>4.5 bits)</div>` : ''}
            ${f.scan_type === 'CONTAINER' ? `<div style="font-size: 12px; background: rgba(77, 255, 136, 0.05); padding: 8px; border-radius: 4px; border-left: 2px solid #4DFF88; margin-bottom: 10px;"><strong>Image Scan:</strong> Package: ${f.affected_package || 'N/A'} (Installed: ${f.installed_version || 'N/A'})</div>` : ''}
            ${f.scan_type === 'NETWORK' ? `<div style="font-size: 12px; background: rgba(153, 102, 255, 0.05); padding: 8px; border-radius: 4px; border-left: 2px solid #9966FF; margin-bottom: 10px;"><strong>Port Scan:</strong> Exposed Service Detected</div>` : ''}
            ${f.scan_type === 'API' ? `<div style="font-size: 12px; background: rgba(0, 188, 212, 0.05); padding: 8px; border-radius: 4px; border-left: 2px solid #00BCD4; margin-bottom: 10px;"><strong>Fuzzer Payload:</strong> Anomalous response behavior observed.</div>` : ''}
            ${f.scan_type === 'MANUAL' ? `<div style="font-size: 12px; background: rgba(255, 219, 77, 0.05); padding: 8px; border-radius: 4px; border-left: 2px solid #FFDB4D; margin-bottom: 10px;"><strong>Human Intel:</strong> Finding validated by Red Team/Security Champion.</div>` : ''}
            <div style="font-size: 11px; margin-bottom: 10px;">
                <span style="color: #FFDB4D;"><i class="ph ph-crosshair"></i> <strong>MITRE ATT&CK:</strong> ${f.mitre_attack?.technique || 'N/A'} (${f.mitre_attack?.technique_id || ''})</span><br>
                <span style="color: #9966FF;"><i class="ph ph-skull"></i> <strong>Real Exploit:</strong> ${f.real_exploit_scenario || 'N/A'}</span>
            </div>

            <!-- [TECHNICAL CORE UPGRADE] -->
            <div style="margin-top: 16px; padding: 12px; border-radius: 8px; background: rgba(255,255,255,0.02); border: 1px solid var(--border-light);">
              <div style="color: #4DFF88; font-size: 11px; margin-bottom: 8px; display: flex; align-items: center; gap: 6px;">
                <i class="ph ph-magic-wand"></i>
                <strong style="text-transform: uppercase; letter-spacing: 0.5px;">Self-Healing Remediation</strong>
              </div>
              <p style="font-size: 13px; color: var(--text-main); margin-bottom: 12px; line-height: 1.5;">${f.remediation_guide || 'Apply standard security patches based on CWE classification.'}</p>

              <div style="color: var(--brand-primary); font-size: 11px; margin-bottom: 8px; display: flex; align-items: center; gap: 6px;">
                <i class="ph ph-fingerprint"></i>
                <strong style="text-transform: uppercase; letter-spacing: 0.5px;">Core Engine Evidence</strong>
              </div>
              <pre style="background: #000; padding: 10px; border-radius: 6px; font-size: 10px; color: #888; overflow-x: auto; font-family: 'JetBrains Mono', monospace; line-height: 1.4;">Confidence: ${f.technical_evidence?.tool_confidence || 'MEDIUM'}\nCaptured: ${f.technical_evidence?.captured_at || 'N/A'}\nSnippet: ${f.technical_evidence?.raw_snippet || 'N/A'}</pre>
            </div>

            ${hasAI ? `<div style="font-size: 13px; background: rgba(255, 107, 0, 0.05); border: 1px solid rgba(255,107,0,0.2); padding: 12px; border-radius: 8px; color: var(--brand-primary); margin-top:12px;"><strong>AI Analysis:</strong> ${f.ai_analysis}</div>` : ''}
          </div>

          <div style="display: flex; gap: 10px; padding-top: 16px; border-top: 1px solid var(--border-light);">
            <button class="btn btn-success" onclick="openModal('modal-verify', '${f.id}')"><i class="ph ph-check"></i> Verify TP</button>
            <button class="btn btn-primary" onclick="openModal('modal-assign', '${f.id}')"><i class="ph ph-user-plus"></i> Assign</button>
            <button class="btn btn-outline" onclick="window.markFP('${f.id}')"><i class="ph ph-x"></i> Mark FP</button>
          </div>
        </div>
      </div>
    `;
  }).join('');
}


function toggleBody(id) {
  const el = document.getElementById(id);
  if (el) el.classList.toggle('open');
}

// ─── Actions (Modals & Buttons) ────────────────────────────────
function openModal(modalId, findingId) {
  appState.pendingActionId = findingId;
  const f = appState.data.findings.find(x => x.id === findingId);
  if (f) {
    const titleEl = document.getElementById(modalId + '-finding');
    if (titleEl) titleEl.textContent = `[${f.id}] ${f.title}`;
  }
  document.getElementById(modalId).classList.add('open');
}

function closeModal(modalId) {
  document.getElementById(modalId).classList.remove('open');
}

window.markFP = function (id) {
  if (!confirm(`Mark ${id} as False Positive?`)) return;
  const f = appState.data.findings.find(x => x.id === id);
  if (f) f.status = 'FALSE_POSITIVE';
  pushAudit('Analyst', 'MARKED_FP', id, 'Marked as False Positive from Action Center');
  renderFindings();
};

function confirmVerify() {
  const f = appState.data.findings.find(x => x.id === appState.pendingActionId);
  if (f) f.status = 'VERIFIED_TP';
  pushAudit(document.getElementById('verify-analyst').value || 'Analyst', 'VERIFIED_TP', f.id, 'Confirmed True Positive');
  closeModal('modal-verify');
  renderFindings();
  renderDevPortal();
}

function confirmAssign() {
  const f = appState.data.findings.find(x => x.id === appState.pendingActionId);
  const dev = document.getElementById('assign-dev').value;
  if (f && dev) {
    f.status = 'ASSIGNED';
    f.assigned_to = dev;
    pushAudit('SecLead', 'ASSIGNED', f.id, `Assigned finding to ${dev}`);
  }
  closeModal('modal-assign');
  renderFindings();
  renderDevPortal();
}

function confirmFixed() {
  const f = appState.data.findings.find(x => x.id === appState.pendingActionId);
  if (f) f.status = 'FIXED';
  pushAudit('Developer', 'FIX_SUBMITTED', f.id, `Fix submitted for validation.`);
  closeModal('modal-fixed');
  renderDevPortal();
}

// ─── Developer Portal ──────────────────────────────────────────
function renderDevPortal() {
  const list = document.getElementById('dev-portal-content');
  if (!list) return;
  const assigned = appState.data.findings.filter(f => f.status === 'ASSIGNED' || f.status === 'VERIFIED_TP' || f.ai_fix);

  if (assigned.length === 0) {
    list.innerHTML = `<div class="card" style="text-align: center;"><p style="color:var(--text-muted)">No active findings assigned to you.</p></div>`;
    return;
  }

  list.innerHTML = assigned.map(f => `
    <div class="card ${f.severity.toLowerCase()}" style="margin-bottom: 16px; border-left: 4px solid ${SEV_COLORS[f.severity]}">
      <div style="font-size: 18px; font-weight: 700; color: var(--text-main); margin-bottom: 8px;">${f.title}</div>
      <div style="font-size: 13px; color: var(--text-muted); margin-bottom: 16px;">Assigned to: ${f.assigned_to || 'You'}</div>

      ${f.ai_fix ? `
      <div class="code-container">
         <div class="code-container-header" style="color: #ef4444; font-size: 11px;">VULNERABLE CODE</div>
         <pre class="code-block code-before">${esc(f.ai_fix.before)}</pre>
      </div>
      <div class="code-container">
         <div class="code-container-header" style="color: #10b981; font-size: 11px;">RECOMMENDED FIX</div>
         <pre class="code-block code-after">${esc(f.ai_fix.after)}</pre>
      </div>
      ` : ''}

      <button class="btn btn-success" onclick="openModal('modal-fixed', '${f.id}')">Submit Fix Code</button>
    </div>
  `).join('');
}

// ─── AI Hub ────────────────────────────────────────────────────
function renderAIList() {
  const list = document.getElementById('ai-list');
  if (!list) return;
  list.innerHTML = appState.data.findings.map(f => {
    const isSelected = appState.selectedFinding === f.id ? 'selected' : '';
    return `<div class="ai-list-item ${isSelected}" onclick="selectAI('${f.id}')">
       <div style="font-weight: 600; font-size: 13px; color: var(--text-main);">${f.title.substring(0, 35)}...</div>
       <div style="font-size: 11px; margin-top:4px; color: var(--text-muted);">${f.id} | Conf: ${f.ai_confidence || 0}%</div>
    </div>`;
  }).join('');
}

function selectAI(id) {
  appState.selectedFinding = id;
  renderAIList();
  const f = appState.data.findings.find(x => x.id === id);
  const detail = document.getElementById('ai-detail');

  if (!f) return;
  detail.innerHTML = `
    <div style="display: flex; gap: 8px; margin-bottom: 16px;">
       ${getSevBadge(f.severity)} ${getBadge('AI Analysis', 'badge-brand')}
    </div>
    <h3 style="font-size: 20px; font-weight: 700; margin-bottom: 16px; color: var(--text-main);">${f.title}</h3>
    <div style="background: var(--bg-surface-hover); padding: 16px; border-radius: 8px; border: 1px solid var(--border-light); margin-bottom: 16px;">
        <h4 style="font-size: 12px; text-transform: uppercase; color: var(--text-muted); margin-bottom: 8px;">Automated Triage Reasoning</h4>
        <p style="font-size: 14px; line-height: 1.5;">${f.ai_analysis || 'No detailed analysis provided.'}</p>
    </div>
    ${f.ai_fix ? `
      <div class="code-container">
         <div class="code-container-header" style="color: #10b981; font-size: 11px;">FIX EXPLANATION</div>
         <pre class="code-block" style="border-left: 3px solid var(--brand-primary);">${f.ai_fix.explanation}</pre>
      </div>
    ` : ''}
  `;
}

// ─── Charts ────────────────────────────────────────────────────
let donutChartInst = null;
let barChartInst = null;

function initCharts() {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  const owaspCounts = {};

  appState.data.findings.forEach(f => {
    if (counts[f.severity] !== undefined) counts[f.severity]++;
    const cat = (f.owasp_2025 || "Unclassified").split(':')[0];
    owaspCounts[cat] = (owaspCounts[cat] || 0) + 1;
  });

  const ctxDonut = document.getElementById('donutChart');
  if (ctxDonut) {
    if (donutChartInst) donutChartInst.destroy();
    donutChartInst = new Chart(ctxDonut, {
      type: 'doughnut',
      data: {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [{ data: [counts.CRITICAL, counts.HIGH, counts.MEDIUM, counts.LOW], backgroundColor: [SEV_COLORS.CRITICAL, SEV_COLORS.HIGH, SEV_COLORS.MEDIUM, SEV_COLORS.LOW], borderWidth: 0 }]
      },
      options: { cutout: '75%', plugins: { legend: { display: false } }, maintainAspectRatio: false }
    });
  }

  const ctxBar = document.getElementById('barChart');
  if (ctxBar) {
    if (barChartInst) barChartInst.destroy();
    const sortedCats = Object.keys(owaspCounts).sort();
    barChartInst = new Chart(ctxBar, {
      type: 'bar',
      data: {
        labels: sortedCats,
        datasets: [{ label: 'Occurrences', data: sortedCats.map(c => owaspCounts[c]), backgroundColor: 'rgba(255, 107, 0, 0.8)', borderRadius: 4 }]
      },
      options: { plugins: { legend: { display: false } }, maintainAspectRatio: false, scales: { y: { beginAtZero: true, grid: { display: false } }, x: { grid: { display: false } } } }
    });
  }
}

// ─── Overrides & Exceptions ────────────────────────────────────
function renderOverride() {
  const container = document.getElementById('blocking-findings');
  if (!container) return;
  const blocks = appState.data.findings.filter(f => f.severity === 'CRITICAL');
  container.innerHTML = blocks.map(f => `
    <div style="padding: 12px; border: 1px solid var(--border-light); border-radius: 8px; margin-bottom: 8px; background: var(--bg-surface);">
       <div style="font-weight: 600; font-size: 13px; color: var(--text-main); margin-bottom: 4px;">${f.title}</div>
       <div style="font-size: 11px; color: var(--text-muted);">${f.id} | CVSS: ${f.cvss_v3}</div>
    </div>
  `).join('');
}

function submitException() {
  if (!document.getElementById('exc-accept').checked) { alert('You must accept risk.'); return; }
  document.getElementById('exception-form-container').style.display = 'none';
  document.getElementById('exception-success').style.display = 'block';
  pushAudit('PM/Lead', 'EXCEPTION_CREATED', 'ALL_CRITICALS', 'Deployment unblocked via risk acceptance.');
}

function resetException() {
  document.getElementById('exception-form-container').style.display = 'block';
  document.getElementById('exception-success').style.display = 'none';
  document.getElementById('exc-accept').checked = false;
}

// ─── Audit Log ─────────────────────────────────────────────────
function pushAudit(actor, action, finding, detail) {
  appState.auditLog.unshift({
    ts: new Date().toISOString().replace('T', ' ').substring(0, 19),
    actor, action, finding, detail
  });
  renderAuditLog();
}

function renderAuditLog() {
  const tbody = document.getElementById('audit-table-body');
  if (!tbody) return;
  tbody.innerHTML = appState.auditLog.map(row => `
    <tr>
      <td class="font-mono" style="font-size:11px;">${row.ts}</td>
      <td style="font-weight: 500;">${row.actor}</td>
      <td>${getBadge(row.action, 'badge-outline')}</td>
      <td class="font-mono" style="font-size:11px;">${row.finding}</td>
      <td>${row.detail}</td>
    </tr>
  `).join('');
}

function exportAuditCSV() {
  const csv = ['Timestamp,Actor,Action,Finding ID,Detail'].concat(appState.auditLog.map(r => `${r.ts},${r.actor},${r.action},${r.finding},"${r.detail}"`)).join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'audit_log.csv'; a.click();
}

// ─── Scanner Control Logic ────────────────────────────────────
async function triggerScan() {
  const target = document.getElementById('scan-target').value;
  const apiKey = document.getElementById('scan-api-key').value;
  const btn = document.getElementById('btn-start-scan');
  const statusText = document.getElementById('scan-status-text');
  const statusIcon = document.querySelector('#scan-status-indicator i');

  if (!target) { alert('Please specify a target path.'); return; }

  // Update UI to loading state
  btn.disabled = true;
  btn.innerHTML = '<i class="ph ph-circle-notch animate-spin"></i> Scanning...';
  statusText.textContent = "Engine Running...";
  statusText.style.color = "var(--brand-primary)";
  statusIcon.className = "ph ph-gauge-high animate-pulse";
  statusIcon.style.color = "var(--brand-primary)";

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, api_key: apiKey })
    });

    if (res.ok) {
      pushAudit('Dashboard', 'SCAN_TRIGGERED', 'ALL', `Target: ${target}`);
      // The scan results will update appState automatically via loadData() polling
    } else {
      throw new Error('Failed to start engine');
    }
  } catch (err) {
    alert('Error triggering scan: ' + err.message);
    resetScannerUI();
  }
}

function resetScannerUI() {
  const btn = document.getElementById('btn-start-scan');
  const statusText = document.getElementById('scan-status-text');
  const statusIcon = document.querySelector('#scan-status-indicator i');

  btn.disabled = false;
  btn.innerHTML = '<i class="ph ph-rocket-launch"></i> Start Penta-Core Scan';
  statusText.textContent = "Engine Ready";
  statusText.style.color = "var(--text-main)";
  statusIcon.className = "ph ph-shield-check";
  statusIcon.style.color = "var(--sev-low)";
}

// ─── Compliance Center ──────────────────────────────────────────
let complianceChartInst = null;

function renderCompliance() {
  const bars = document.getElementById('compliance-bars');
  const details = document.getElementById('compliance-details-list');
  if (!bars || !appState.policy || !appState.policy.compliance_summary) return;

  const frameworks = appState.policy.compliance_summary.frameworks;
  const fwNames = Object.keys(frameworks);

  bars.innerHTML = fwNames.map(fw => {
    const items = frameworks[fw];
    const progress = items.length > 5 ? 30 : (items.length > 0 ? 60 : 100);
    const color = progress < 50 ? 'var(--sev-critical)' : (progress < 80 ? 'var(--sev-high)' : 'var(--sev-low)');

    return `
      <div style="margin-bottom: 20px;">
        <div style="display: flex; justify-content: space-between; margin-bottom: 6px; font-size: 13px;">
          <span style="font-weight: 600;">${fw}</span>
          <span style="color: ${color}; font-weight: 700;">${progress}% Compliant</span>
        </div>
        <div style="height: 8px; background: var(--bg-surface-hover); border-radius: 4px; overflow: hidden;">
          <div style="height: 100%; width: ${progress}%; background: ${color}; transition: width 1s ease-in-out;"></div>
        </div>
      </div>
    `;
  }).join('');

  details.innerHTML = fwNames.map(fw => `
    <div style="margin-bottom: 24px;">
      <h4 style="font-size: 14px; color: var(--text-main); margin-bottom: 12px; border-bottom: 1px solid var(--border-light); padding-bottom: 8px;">
        ${fw} Requirements & Controls
      </h4>
      <div style="display: flex; flex-direction: column; gap: 8px;">
        ${frameworks[fw].length > 0
          ? frameworks[fw].map(item => `
            <div style="padding: 10px; background: var(--bg-surface-hover); border-radius: 6px; border-left: 3px solid var(--brand-primary);">
                <div style="font-weight: 700; font-size: 12px; color: var(--brand-primary);">${item.clause}</div>
                <div style="font-size: 11px; color: var(--text-main);">${item.control}</div>
            </div>
          `).join('')
          : '<span style="color: var(--text-muted); font-size: 12px;">No active violations found.</span>'}
      </div>
    </div>
  `).join('');

  initComplianceChart();
}

function initComplianceChart() {
  const ctx = document.getElementById('complianceChart');
  if (!ctx || !appState.policy || !appState.policy.compliance_summary) return;

  const frameworks = appState.policy.compliance_summary.frameworks;
  const labels = Object.keys(frameworks);
  const data = labels.map(l => frameworks[l].length);

  if (complianceChartInst) complianceChartInst.destroy();
  complianceChartInst = new Chart(ctx, {
    type: 'radar',
    data: {
      labels: labels,
      datasets: [{
        label: 'Policy Violations',
        data: data,
        backgroundColor: 'rgba(255, 107, 0, 0.2)',
        borderColor: 'rgba(255, 107, 0, 1)',
        borderWidth: 2,
        pointBackgroundColor: 'rgba(255, 107, 0, 1)'
      }]
    },
    options: {
      maintainAspectRatio: false,
      scales: {
        r: {
          beginAtZero: true,
          grid: { color: 'rgba(255,255,255,0.05)' },
          angleLines: { color: 'rgba(255,255,255,0.05)' },
          ticks: { display: false }
        }
      },
      plugins: { legend: { display: false } }
    }
  });
}

// ─── Real-time Status Polling ────────────────────────────────
setInterval(async () => {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    const btn = document.getElementById('btn-start-scan');
    const statusText = document.getElementById('scan-status-text');
    const statusIcon = document.querySelector('#scan-status-indicator i');

    if (data.is_scanning) {
      if (btn && !btn.disabled) {
        btn.disabled = true;
        btn.innerHTML = '<i class="ph ph-circle-notch animate-spin"></i> Engine Running...';
        statusText.textContent = "Engine Busy - Scanning...";
        statusIcon.className = "ph ph-gauge-high animate-pulse";
      }
    } else {
      if (btn && btn.disabled) {
        resetScannerUI();
        alert("✅ Security Scan Completed! Dashboard has been updated.");
        loadData();
      }
    }
  } catch (err) { }
}, 2000);

function renderMaturity() {
  if (!appState.policy || !appState.policy.compliance_summary || !appState.policy.compliance_summary.maturity_scores) return;

  const scores = appState.policy.compliance_summary.maturity_scores;

  const mapping = {
    'mat-gov': { score: scores["Governance (ISO/CIS)"], label: "ISO 27034 L" },
    'mat-found': { score: scores["Foundation (NIST)"], label: "NIST SSDF L" },
    'mat-appsec': { score: scores["AppSec (OWASP)"], label: "OWASP ASVS L" },
    'mat-supply': { score: scores["Supply Chain (SLSA)"], label: "SLSA v1.1 L" },
    'mat-pipeline': { score: 80, label: "Gate Strength L" } // Mocked pipeline score
  };

  for (const [id, cfg] of Object.entries(mapping)) {
    const el = document.getElementById(id);
    if (el) {
      const level = Math.floor(cfg.score / 25) || 1;
      el.innerText = `${cfg.label}${level}`;
      el.style.background = cfg.score > 70 ? 'rgba(77, 255, 136, 0.1)' : 'rgba(255, 107, 0, 0.1)';
      el.style.color = cfg.score > 70 ? '#4dff88' : 'var(--brand-primary)';
      el.style.border = `1px solid ${cfg.score > 70 ? '#4dff88' : 'var(--brand-primary)'}`;
    }
  }
}

let strideChartInst = null;
function initCharts() {
  const findings = appState.data.findings;

  // Severity Distribution
  const sevCtx = document.getElementById('severityChart');
  if (sevCtx) {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    findings.forEach(f => { if (counts[f.severity] !== undefined) counts[f.severity]++; });

    if (window.sevChartInst) window.sevChartInst.destroy();
    window.sevChartInst = new Chart(sevCtx, {
      type: 'doughnut',
      data: {
        labels: Object.keys(counts),
        datasets: [{
          data: Object.values(counts),
          backgroundColor: ['#ff4d4d', '#ff944d', '#ffdb4d', '#4dff88'],
          borderWidth: 0
        }]
      },
      options: { cutout: '75%', plugins: { legend: { position: 'bottom' } } }
    });
  }

  // STRIDE Chart
  const strideCtx = document.getElementById('strideChart');
  if (strideCtx) {
    const sCounts = { 'Spoofing': 0, 'Tampering': 0, 'Repudiation': 0, 'Info Disclosure': 0, 'DoS': 0, 'EoP': 0 };
    findings.forEach(f => {
      const cat = f.stride_category || '';
      if (cat.includes('Spoofing')) sCounts['Spoofing']++;
      if (cat.includes('Tampering')) sCounts['Tampering']++;
      if (cat.includes('Repudiation')) sCounts['Repudiation']++;
      if (cat.includes('Information')) sCounts['Info Disclosure']++;
      if (cat.includes('Service')) sCounts['DoS']++;
      if (cat.includes('Elevation')) sCounts['EoP']++;
    });

    if (strideChartInst) strideChartInst.destroy();
    strideChartInst = new Chart(strideCtx, {
      type: 'radar',
      data: {
        labels: Object.keys(sCounts),
        datasets: [{
          label: 'Threat Vector Count',
          data: Object.values(sCounts),
          backgroundColor: 'rgba(0, 188, 212, 0.2)',
          borderColor: 'rgba(0, 188, 212, 1)',
          borderWidth: 2,
          pointBackgroundColor: 'rgba(0, 188, 212, 1)'
        }]
      },
      options: {
        scales: { r: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { display: false } } },
        plugins: { legend: { display: false } }
      }
    });
  }
}
