// AegisFlow - Unified Enterprise Security Dashboard Logic
// Built for AppSec Excellence & Task 1-5 Compliance

const appState = {
  data: {
    findings: [],
    policy: {},
    audit: [],
    status: {
        is_scanning: false,
        sast: 'pending', sca: 'pending', iac: 'pending', dast: 'pending', secret: 'pending'
    }
  },
  filters: { severity: 'all' },
  currentTab: 'executive',
  selectedTargetUrl: ''
};

function safeArray(value) {
    return Array.isArray(value) ? value : [];
}

function normalizeFindings(payload) {
    if (Array.isArray(payload)) return payload;
    if (payload && Array.isArray(payload.findings)) return payload.findings;
    return [];
}

function normalizePolicy(payload) {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return {};

    const statusLabel = payload.pipeline_status || payload.status || 'UNKNOWN';
    const isBlocked = String(statusLabel).toUpperCase() === 'BLOCKED';

    return {
        ...payload,
        passed: payload.passed ?? !isBlocked,
        statusLabel
    };
}

function normalizeAudit(payload) {
    return safeArray(payload).map((entry) => ({
        timestamp: entry.timestamp || '-',
        actor: entry.actor || entry.user || 'system-agent',
        action: entry.action || entry.event_type || 'PIPELINE_EVENT',
        finding_id: entry.finding_id || entry.pipeline_id || '-',
        detail: entry.detail || entry.outcome || JSON.stringify(entry.findings_summary || {})
    }));
}

function updateScanMeta(meta = {}) {
    const projectName = document.getElementById('project-name');
    const scanMeta = document.getElementById('scan-meta');
    const targetDisplay = document.getElementById('current-target-display');

    const appName = meta.app_name || meta.target_name || appState.lastTarget?.split('/').pop() || 'No target selected';
    const scanId = meta.pipeline_run_id || meta.scan_id || 'N/A';
    const branch = meta.branch || 'main';
    const scanTime = meta.generated_at || meta.scan_date || meta.timestamp || 'N/A';

    if (projectName) projectName.innerText = `Project: ${appName}`;
    if (scanMeta) scanMeta.innerText = `Scan: ${scanTime} · Run: ${scanId} · Branch: ${branch}`;
    if (targetDisplay) targetDisplay.innerText = appName;
}

async function fetchJsonWithFallback(urls, fallbackValue) {
    for (const url of urls) {
        try {
            const res = await fetch(url);
            if (res.ok) return await res.json();
        } catch (err) {
            console.warn(`[DASHBOARD] Fetch failed for ${url}:`, err);
        }
    }

    return fallbackValue;
}

const UI_CONFIG = {
  colors: {
    CRITICAL: '#ef4444',
    HIGH: '#f59e0b',
    MEDIUM: '#3b82f6',
    LOW: '#10b981'
  }
};

// ─── Data Engine ───────────────────────────────────────────────
async function loadData() {
  try {
    const timestamp = Date.now();
    console.log(`[DASHBOARD] Syncing Full State...`);

    const [findingsPayload, policyPayload, auditPayload, statusPayload] = await Promise.all([
      fetchJsonWithFallback([
        `/data/full_report_triaged.json?v=${timestamp}`,
        `/data/full_report.json?v=${timestamp}`
      ], { findings: [] }),
      fetchJsonWithFallback([`/data/policy_result.json?v=${timestamp}`], {}),
      fetchJsonWithFallback([`/data/audit_log.json?v=${timestamp}`], []),
      fetchJsonWithFallback([`/api/status?v=${timestamp}`], {})
    ]);

    appState.data.findings = normalizeFindings(findingsPayload);
    appState.data.policy = normalizePolicy(policyPayload);
    appState.data.audit = normalizeAudit(auditPayload);
    appState.data.status = statusPayload;
    appState.data.scanMeta = findingsPayload?.scan_metadata || {};

    console.log(`[DASHBOARD] Ingested ${appState.data.findings.length} findings.`);

    refreshUI();

  } catch (err) {
    console.warn("[DASHBOARD] Sync Error:", err);
  }
}

function refreshUI() {
    const f = appState.data.findings || [];
    const s = {
        critical: f.filter(x => x.severity === 'CRITICAL').length,
        high: f.filter(x => x.severity === 'HIGH').length,
        medium: f.filter(x => x.severity === 'MEDIUM').length,
        low: f.filter(x => x.severity === 'LOW').length,
        total: f.length
    };

    updateExecutiveCards(s);
    renderMainCharts(s);
    renderFindingsList();
    updateChecklist();
    updateKPIs();
    updateProgressUI();
    renderAuditLog();
    renderReportPreview();

    updateScanMeta(appState.data.scanMeta);
}

/**
 * Renders a high-fidelity preview of the Security Assessment Report.
 */
function renderReportPreview() {
    const preview = document.getElementById('report-preview');
    if (!preview) {
        console.warn("[REPORT] Preview container not found");
        return;
    }

    console.log("[REPORT] Rendering preview...");
    const findings = appState.data.findings || [];
    const meta = appState.data.scanMeta || {};
    const stats = appState.data.status || {};

    const criticals = findings.filter(f => f.severity === 'CRITICAL');
    const highs = findings.filter(f => f.severity === 'HIGH');

    // Professional Security Report Template
    preview.innerHTML = `
        <div class="report-document" style="max-width: 900px; margin: 0 auto; color: #1e293b; line-height: 1.6; font-family: 'Inter', -apple-system, sans-serif; background: #fff; padding: 10px;">
            <!-- Header Section -->
            <div style="display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 4px solid #ff6b00; padding-bottom: 24px; margin-bottom: 40px;">
                <div>
                    <h1 style="color: #ff6b00; font-size: 32px; margin: 0 0 8px 0; font-weight: 800; letter-spacing: -1px;">SECURITY ASSESSMENT</h1>
                    <div style="font-size: 14px; color: #64748b; font-weight: 600; text-transform: uppercase; letter-spacing: 1px;">
                        Report ID: ${meta.pipeline_run_id && meta.pipeline_run_id !== 'pending' ? meta.pipeline_run_id : 'AF-PRD-' + Math.random().toString(36).substr(2, 6).toUpperCase()}
                    </div>
                </div>
                <div style="text-align: right;">
                    <div style="font-weight: 900; font-size: 20px; color: #0f172a; margin-bottom: 4px;">AEGISFLOW ENTERPRISE</div>
                    <div style="font-size: 14px; color: #64748b; font-weight: 500;">Generated: ${new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}</div>
                </div>
            </div>

            <!-- 1. Executive Summary -->
            <section style="margin-bottom: 48px;">
                <h2 style="font-size: 20px; color: #0f172a; border-left: 5px solid #ff6b00; padding-left: 15px; margin-bottom: 24px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.5px;">1. Executive Summary</h2>
                <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 16px; padding: 32px;">
                    <p style="font-size: 16px; color: #334155; margin-bottom: 32px; font-weight: 500;">
                        This automated assessment analyzes the security posture of <span style="color: #ff6b00; font-weight: 700;">${meta.app_name || 'Autonomous Target'}</span>.
                        The engine evaluated SAST patterns, SCA dependencies, Hardcoded Secrets, and Infrastructure configurations.
                    </p>

                    <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 24px;">
                        <div style="background: #fff; border: 1px solid #e2e8f0; padding: 24px; border-radius: 12px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.02);">
                            <div style="font-size: 11px; text-transform: uppercase; font-weight: 800; color: #64748b; margin-bottom: 12px; letter-spacing: 1px;">Security Score</div>
                            <div style="font-size: 40px; font-weight: 900; color: ${(stats.security_score || 0) < 70 ? '#ef4444' : '#10b981'};">
                                ${stats.security_score || '--'}<span style="font-size: 20px; color: #94a3b8;">/100</span>
                            </div>
                        </div>
                        <div style="background: #fff; border: 1px solid #fee2e2; padding: 24px; border-radius: 12px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.02);">
                            <div style="font-size: 11px; text-transform: uppercase; font-weight: 800; color: #991b1b; margin-bottom: 12px; letter-spacing: 1px;">Critical Risks</div>
                            <div style="font-size: 40px; font-weight: 900; color: #ef4444;">${criticals.length}</div>
                        </div>
                        <div style="background: #fff; border: 1px solid #ffedd5; padding: 24px; border-radius: 12px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.02);">
                            <div style="font-size: 11px; text-transform: uppercase; font-weight: 800; color: #9a3412; margin-bottom: 12px; letter-spacing: 1px;">High Risks</div>
                            <div style="font-size: 40px; font-weight: 900; color: #f97316;">${highs.length}</div>
                        </div>
                    </div>
                </div>
            </section>

            <!-- 2. Priority Risk Analysis -->
            <section style="margin-bottom: 48px;">
                <h2 style="font-size: 20px; color: #0f172a; border-left: 5px solid #ff6b00; padding-left: 15px; margin-bottom: 24px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.5px;">2. Priority Risk Analysis</h2>
                <div style="overflow: hidden; border: 1px solid #e2e8f0; border-radius: 16px;">
                    <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
                        <thead>
                            <tr style="background: #f1f5f9;">
                                <th style="padding: 16px; text-align: left; font-weight: 800; color: #475569; border-bottom: 2px solid #e2e8f0;">Severity</th>
                                <th style="padding: 16px; text-align: left; font-weight: 800; color: #475569; border-bottom: 2px solid #e2e8f0;">Vulnerability Details</th>
                                <th style="padding: 16px; text-align: left; font-weight: 800; color: #475569; border-bottom: 2px solid #e2e8f0;">Business Impact</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${findings.length === 0 ? `
                                <tr>
                                    <td colspan="3" style="padding: 40px; text-align: center; color: #64748b; font-weight: 500;">
                                        No active findings detected for this target.
                                    </td>
                                </tr>
                            ` : findings.slice(0, 10).map(f => `
                                <tr style="border-bottom: 1px solid #f1f5f9;">
                                    <td style="padding: 16px; vertical-align: top;">
                                        <div style="display: inline-block; font-size: 10px; font-weight: 900; padding: 4px 10px; border-radius: 6px; background: ${f.severity === 'CRITICAL' ? '#fee2e2' : '#ffedd5'}; color: ${f.severity === 'CRITICAL' ? '#991b1b' : '#9a3412'}; border: 1px solid ${f.severity === 'CRITICAL' ? '#fecaca' : '#fed7aa'};">
                                            ${f.severity}
                                        </div>
                                    </td>
                                    <td style="padding: 16px; vertical-align: top;">
                                        <div style="font-weight: 800; font-size: 15px; color: #0f172a; margin-bottom: 6px;">${f.title}</div>
                                        <div style="font-size: 12px; color: #64748b; font-family: 'JetBrains Mono', monospace;">${f.affected_file}:${f.affected_line}</div>
                                    </td>
                                    <td style="padding: 16px; vertical-align: top; font-size: 13px; color: #475569; max-width: 250px;">
                                        ${f.business_impact || 'Potential unauthorized access or full system compromise.'}
                                    </td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
                ${findings.length > 10 ? `<p style="margin-top: 20px; font-size: 13px; color: #64748b; font-weight: 500; text-align: center;">... displaying top 10 of ${findings.length} findings ...</p>` : ''}
            </section>

            <!-- Footer Section -->
            <div style="margin-top: 80px; padding-top: 32px; border-top: 2px solid #f1f5f9; text-align: center;">
                <div style="font-weight: 800; font-size: 14px; color: #0f172a; margin-bottom: 8px;">AEGISFLOW AUTONOMOUS PIPELINE</div>
                <div style="font-size: 12px; color: #94a3b8; font-weight: 500;">
                    This document is automatically generated and contains confidential security information. <br/>
                    &copy; ${new Date().getFullYear()} AegisFlow Enterprise. All rights reserved.
                </div>
            </div>
        </div>
    `;
}

function updateProgressUI() {
    const container = document.getElementById('progress-container');
    const bar = document.getElementById('progress-bar');
    const label = document.getElementById('progress-status');
    const percentEl = document.getElementById('progress-percent');
    if (!container || !bar || !label || !percentEl) return;

    const status = appState.data.status || {};
    const stages = [
        { key: 'sast', label: 'Running SAST analysis' },
        { key: 'sca', label: 'Running dependency scan' },
        { key: 'sbom', label: 'Generating SBOM' },
        { key: 'secret', label: 'Scanning secrets' },
        { key: 'iac', label: 'Scanning IaC and Dockerfile' },
        { key: 'dast', label: 'Running DAST checks' }
    ];

    if (!status.is_scanning) {
        container.style.display = 'none';
        bar.style.width = '0%';
        percentEl.innerText = '0%';
        label.innerText = 'Initializing Security Pipeline...';
        return;
    }

    container.style.display = 'block';

    let completed = 0;
    let currentLabel = 'Initializing Security Pipeline...';
    let runningFound = false;

    for (const stage of stages) {
        const value = status[stage.key];
        if (value === 'completed') {
            completed += 1;
            continue;
        }
        if (!runningFound && value === 'running') {
            currentLabel = stage.label;
            runningFound = true;
        }
    }

    if (!runningFound && completed === stages.length) {
        currentLabel = 'Finalizing policy and reports';
    } else if (!runningFound && completed > 0) {
        currentLabel = 'Advancing to next security stage';
    }

    const percent = Math.max(5, Math.min(100, Math.round((completed / stages.length) * 100)));
    bar.style.width = `${percent}%`;
    percentEl.innerText = `${percent}%`;
    label.innerText = currentLabel;
}

function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function formatPathWithLine(finding) {
    const file = finding.affected_file || finding.file || finding.url || finding.affected_url || 'N/A';
    const line = finding.affected_line;
    if (line === undefined || line === null || line === 0 || file === 'N/A') return file;
    return `${file}:${line}`;
}

function formatCvss(finding) {
    const cvss = finding.cvss_v3 ?? finding.cvss;
    return cvss === undefined || cvss === null ? 'N/A' : cvss;
}

function formatBadge(label, className = 'badge-outline') {
    if (!label) return '';
    return `<span class="badge ${className}">${escapeHtml(label)}</span>`;
}

function formatMitre(finding) {
    const mitre = finding.mitre_attack;
    if (!mitre || typeof mitre !== 'object') return 'N/A';
    const tactic = [mitre.tactic_id, mitre.tactic].filter(Boolean).join(' ');
    const technique = [mitre.technique_id, mitre.technique].filter(Boolean).join(' ');
    return [tactic, technique].filter(Boolean).join(' · ') || 'N/A';
}

function formatAiFix(finding) {
    const fix = finding.ai_fix;
    if (!fix || typeof fix !== 'object') return '';

    const parts = [];
    if (fix.explanation) parts.push(`<div style="margin-bottom: 10px;">${escapeHtml(fix.explanation)}</div>`);
    if (fix.after) {
        parts.push(`
            <div style="margin-top: 10px;">
                <div style="font-size: 11px; font-weight: 700; margin-bottom: 6px; text-transform: uppercase;">Suggested Fix</div>
                <pre style="white-space: pre-wrap; overflow-x: auto; margin: 0; font-size: 11px; line-height: 1.45;">${escapeHtml(fix.after)}</pre>
            </div>
        `);
    }

    return parts.join('');
}

function normalizeTargetPath(rawTarget) {
    if (!rawTarget) return '';

    let normalized = String(rawTarget).trim().replace(/\\/g, '/');
    const marker = '/real-apps/';
    const markerIndex = normalized.lastIndexOf(marker);

    if (markerIndex >= 0) {
        normalized = `.${normalized.slice(markerIndex)}`;
    }

    if (normalized.startsWith('/real-apps/')) {
        normalized = `.${normalized}`;
    }

    if (!normalized.startsWith('./')) {
        normalized = `./${normalized.replace(/^\.?\//, '')}`;
    }

    return normalized;
}

function inferTargetUrl(target) {
    if (!target) return '';
    const normalized = normalizeTargetPath(target).toLowerCase();

    if (normalized.includes('juice-shop')) {
        return 'http://juice-shop:3000';
    }

    // Non-containerized demo targets should avoid accidentally reusing Juice Shop as DAST target.
    return '';
}

function openProjectBrowser() {
    const modal = document.getElementById('project-modal');
    if (modal) modal.style.display = 'flex';
}

function closeProjectBrowser() {
    const modal = document.getElementById('project-modal');
    if (modal) modal.style.display = 'none';
}

function selectProject(projectPath) {
    const normalizedTarget = normalizeTargetPath(projectPath);
    const targetInput = document.getElementById('scanTarget');
    if (targetInput) targetInput.value = normalizedTarget;
    appState.lastTarget = normalizedTarget;
    appState.selectedTargetUrl = inferTargetUrl(normalizedTarget);
    closeProjectBrowser();
}

function toggleAIField() {
    const toggle = document.getElementById('ai-toggle');
    const container = document.getElementById('ai-key-container');
    if (!toggle || !container) return;
    container.style.opacity = toggle.checked ? '1' : '0.45';
}

function renderFindingDetails(finding) {
    const evidence = finding.code_snippet || finding.technical_evidence?.raw_snippet || '';
    const metadata = [
        finding.source_tool || finding.tool,
        finding.scan_type,
        finding.cve_cwe,
        finding.owasp_2025 || finding.owasp
    ].filter(Boolean);

    const references = [
        ['File', formatPathWithLine(finding)],
        ['CVSS', formatCvss(finding)],
        ['EPSS', finding.epss_score ?? 'N/A'],
        ['MITRE ATT&CK', formatMitre(finding)],
        ['Compliance', finding.compliance_controls || 'N/A'],
        ['SLA', finding.sla_deadline || 'N/A']
    ];

    return `
        <div style="display: grid; grid-template-columns: 1.2fr 1fr; gap: 20px;">
            <div>
                <h5 style="margin-bottom: 8px; font-size: 12px; text-transform: uppercase; color: #64748b;">Description & Impact</h5>
                <p style="font-size: 13px; color: #334155; margin-bottom: 12px;">${escapeHtml(finding.business_impact || finding.impact || finding.description || 'No detailed impact analysis available.')}</p>
                <div style="display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 12px;">
                    ${metadata.map(label => formatBadge(label)).join('')}
                </div>
                <div style="display: grid; grid-template-columns: 140px 1fr; gap: 8px 12px; font-size: 12px;">
                    ${references.map(([label, value]) => `
                        <div style="color: #64748b; font-weight: 600;">${escapeHtml(label)}</div>
                        <div style="color: #0f172a;">${escapeHtml(value)}</div>
                    `).join('')}
                </div>
            </div>
            <div>
                <h5 style="margin-bottom: 8px; font-size: 12px; text-transform: uppercase; color: #10b981;">AI Remediation Plan</h5>
                <div style="background: rgba(16, 185, 129, 0.05); padding: 12px; border-radius: 6px; font-size: 12px; color: #047857; border: 1px solid rgba(16, 185, 129, 0.2);">
                    <div>${escapeHtml(finding.remediation_hint || finding.remediation || 'Consult security documentation for remediation steps.')}</div>
                    ${formatAiFix(finding)}
                </div>
            </div>
        </div>
        ${(finding.ai_analysis || evidence) ? `
            <div style="margin-top: 16px; display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                <div>
                    <h5 style="margin-bottom: 8px; font-size: 12px; text-transform: uppercase; color: #64748b;">AI Analysis</h5>
                    <p style="font-size: 12px; color: #334155;">${escapeHtml(finding.ai_analysis || 'N/A')}</p>
                </div>
                <div>
                    <h5 style="margin-bottom: 8px; font-size: 12px; text-transform: uppercase; color: #64748b;">Evidence / Snippet</h5>
                    <pre style="background: #0f172a; color: #e2e8f0; padding: 12px; border-radius: 8px; font-size: 11px; line-height: 1.4; white-space: pre-wrap; overflow-x: auto; margin: 0;">${escapeHtml(evidence || 'N/A')}</pre>
                </div>
            </div>
        ` : ''}
    `;
}

// ─── UI Components ──────────────────────────────────────────────
function updateExecutiveCards(s) {
    // Security Score (Task 3 logic)
    const scoreVal = Math.max(0, 100 - (s.critical * 20) - (s.high * 10) - (s.medium * 2));
    const scoreEl = document.getElementById('score-value');
    if (scoreEl) {
        scoreEl.innerHTML = `${scoreVal}<span style="font-size: 16px; color: var(--text-muted);">/100</span>`;
        const badge = document.getElementById('grade-badge');
        if (badge) {
            if (scoreVal < 50) { badge.innerText = 'CRITICAL RISK'; badge.className = 'badge badge-critical'; }
            else if (scoreVal < 80) { badge.innerText = 'NEEDS ATTENTION'; badge.className = 'badge badge-high'; }
            else { badge.innerText = 'SECURE'; badge.className = 'badge badge-success'; }
        }
    }

    // Critical Findings Card
    const critEl = document.querySelector('.card-alert-red .stat-value.blink');
    if (critEl) critEl.innerText = s.critical;

    // Pending Triage Card
    const pendingEl = document.getElementById('kpi-pending');
    if (pendingEl) pendingEl.innerText = fCount('ai_triaged', true);
}

function fCount(key, val) {
    return appState.data.findings.filter(f => f[key] === val).length;
}

function renderMainCharts(s) {
    // Doughnut Chart (Severity)
    const ctxDonut = document.getElementById('donutChart');
    if (ctxDonut) {
        if (window.myDonut) window.myDonut.destroy();
        window.myDonut = new Chart(ctxDonut, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [s.critical, s.high, s.medium, s.low],
                    backgroundColor: [UI_CONFIG.colors.CRITICAL, UI_CONFIG.colors.HIGH, UI_CONFIG.colors.MEDIUM, UI_CONFIG.colors.LOW],
                    borderWidth: 0
                }]
            },
            options: { cutout: '75%', plugins: { legend: { display: false } } }
        });
    }

    // Bar Chart (OWASP Top 10)
    const ctxBar = document.getElementById('barChart');
    if (ctxBar) {
        const owasp = {};
        appState.data.findings.forEach(f => {
            const cat = f.owasp || 'A00:Other';
            owasp[cat] = (owasp[cat] || 0) + 1;
        });

        if (window.myBar) window.myBar.destroy();
        window.myBar = new Chart(ctxBar, {
            type: 'bar',
            data: {
                labels: Object.keys(owasp),
                datasets: [{
                    label: 'Findings',
                    data: Object.values(owasp),
                    backgroundColor: UI_CONFIG.colors.MEDIUM,
                    borderRadius: 4
                }]
            },
            options: { indexAxis: 'y', plugins: { legend: { display: false } } }
        });
    }
}

function updateChecklist() {
    const status = appState.data.status || {};
    const mapping = {
        'sast': 'sast-status',
        'sca': 'sca-status',
        'iac': 'iac-status',
        'dast': 'dast-status',
        'api': 'api-status'
    };

    Object.keys(mapping).forEach(key => {
        const el = document.getElementById(mapping[key]);
        if (!el) return;
        const state = status[key] || 'pending';
        if (state === 'running') el.innerHTML = '<i class="ph ph-circle-notch animate-spin" style="color: var(--brand-primary);"></i>';
        else if (state === 'completed') el.innerHTML = '<i class="ph ph-check-circle" style="color: #4dff88;"></i>';
        else el.innerHTML = '<i class="ph ph-circle" style="color: #666;"></i>';
    });
}

function updateKPIs() {
    const gateEl = document.getElementById('kpi-gate');
    if (gateEl) {
        const passed = appState.data.policy.passed !== false;
        gateEl.innerText = appState.data.policy.statusLabel || (passed ? "PASSED" : "FAIL");
        gateEl.style.color = passed ? '#4dff88' : '#ef4444';
    }

    // Mock KPIs for Demo
    document.getElementById('kpi-mttd').innerText = "1.2h";
    document.getElementById('kpi-mttr').innerText = "4.5h";
    document.getElementById('kpi-ver').innerText = "0.5%";
}

function renderFindingsList() {
    const container = document.getElementById('findings-list');
    if (!container) return;

    const filtered = appState.data.findings.filter(f => {
        return appState.filters.severity === 'all' || f.severity === appState.filters.severity;
    });

    if (filtered.length === 0) {
        container.innerHTML = '<div style="text-align: center; padding: 40px; color: #888;">No findings detected. System Clear.</div>';
        const msg = document.getElementById('action-counts');
        if (msg) msg.innerText = "All checks passed.";
        return;
    }

    const msg = document.getElementById('action-counts');
    if (msg) msg.innerText = `Detected ${filtered.length} vulnerabilities requiring triage.`;

    container.innerHTML = filtered.map(f => `
        <div class="finding-card ${f.severity.toLowerCase()}">
            <div class="finding-header" onclick="toggleDetails('${f.id}')">
                <div style="flex: 1;">
                    <div style="display: flex; gap: 8px; margin-bottom: 6px;">
                        <span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span>
                        ${f.status === 'AI_TRIAGED' ? '<span class="badge" style="background: rgba(245,158,11,0.1); color: #f59e0b;">AI TRIAGED</span>' : ''}
                        <span class="badge" style="background: rgba(255,255,255,0.05); color: #888;">${f.source_tool || f.tool || 'Engine'}</span>
                    </div>
                    <h4 style="margin: 0; font-size: 14px;">${f.title}</h4>
                    <div style="font-size: 11px; color: #666; font-family: monospace; margin-top: 4px;">${formatPathWithLine(f)}</div>
                </div>
                <div style="text-align: right; margin-right: 15px;">
                    <div style="font-weight: 700; color: var(--sev-${f.severity.toLowerCase()});">CVSS ${formatCvss(f)}</div>
                </div>
                <i class="ph ph-caret-down" id="icon-${f.id}"></i>
            </div>
            <div id="details-${f.id}" class="finding-details" style="display: none; padding: 20px; border-top: 1px solid var(--border-light);">
                ${renderFindingDetails(f)}
            </div>
        </div>
    `).join('');
}

function toggleDetails(id) {
    const el = document.getElementById('details-' + id);
    const icon = document.getElementById('icon-' + id);
    if (el) {
        const isHidden = el.style.display === 'none';
        el.style.display = isHidden ? 'block' : 'none';
        if (icon) icon.style.transform = isHidden ? 'rotate(180deg)' : 'rotate(0)';
    }
}

function renderAuditLog() {
    const body = document.getElementById('audit-table-body');
    if (!body) return;
    body.innerHTML = appState.data.audit.map(a => `
        <tr>
            <td style="color: #888;">${a.timestamp}</td>
            <td style="font-weight: 600;">${a.actor}</td>
            <td><span class="badge" style="background: rgba(255,255,255,0.05);">${a.action}</span></td>
            <td>${a.finding_id || '-'}</td>
            <td style="font-size: 12px; color: #aaa;">${a.detail}</td>
        </tr>
    `).join('');
}

// ─── Actions ──────────────────────────────────────────────────
async function triggerScan() {
    console.log("[UI] Launching Autonomous Arsenal...");
    const targetEl = document.getElementById('scanTarget');
    if (!targetEl) return console.error("Target input not found!");

    const target = normalizeTargetPath(targetEl.value);
    if (!target) {
        const msg = document.getElementById('scan-status-msg');
        if (msg) msg.innerText = 'Select or enter a target path before launching the scan.';
        targetEl.focus();
        return;
    }
    targetEl.value = target;
    appState.lastTarget = target;
    appState.selectedTargetUrl = inferTargetUrl(target);

    const aiToggle = document.getElementById('ai-toggle');
    const apiKeyInput = document.getElementById('api-key-input');
    const useAI = aiToggle ? aiToggle.checked : true;
    const apiKey = useAI && apiKeyInput ? apiKeyInput.value.trim() : '';

    // UI Feedback
    const btn = document.getElementById('launchBtn');
    const msg = document.getElementById('scan-status-msg');
    if (btn) btn.disabled = true;
    if (msg) msg.innerHTML = '<i class="ph ph-circle-notch animate-spin"></i> PIPELINE LAUNCHED...';
    appState.data.findings = [];
    appState.data.scanMeta = {
        app_name: target.split('/').pop(),
        pipeline_run_id: 'pending',
        generated_at: 'Pending',
        branch: 'main'
    };
    refreshUI();

    try {
        const res = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target: target,
                target_url: appState.selectedTargetUrl,
                use_ai: useAI,
                groq_key: apiKey
            })
        });

        const data = await res.json();
        console.log("[SERVER] Scan Status:", data);
        if (data.status === 'SCAN_STARTED') {
            appState.isScanning = true;
            loadData();
        }
    } catch (err) {
        console.error("[UI] Launch Failed:", err);
        if (btn) btn.disabled = false;
        if (msg) msg.innerText = "Launch Failed. Check Connection.";
    }
}

function switchTab(tabId) {
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    const panel = document.getElementById('tab-' + tabId);
    const nav = document.getElementById('nav-' + tabId);
    if (panel) panel.classList.add('active');
    if (nav) nav.classList.add('active');

    if (tabId === 'reports') {
        renderReportPreview();
    }
}

function setFilter(key, val, btn) {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    appState.filters[key] = val;
    renderFindingsList();
}

// ─── Initialization ──────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    loadData();

    // Polling Logic
    setInterval(async () => {
        try {
            const res = await fetch('/api/status');
            const data = await res.json();

            // Only reload if status changes or while scanning
            if (data.is_scanning || data.is_scanning !== appState.isScanning) {
                appState.isScanning = data.is_scanning;
                appState.data.status = data; // Sync the full status object

                const btn = document.getElementById('launchBtn');
                const msg = document.getElementById('scan-status-msg');
                const progContainer = document.getElementById('progress-container');
                const progStatus = document.getElementById('progress-status');

                if (btn) {
                    btn.disabled = data.is_scanning;
                    if (data.is_scanning) {
                        btn.innerHTML = '<i class="ph ph-circle-notch animate-spin" style="font-size: 22px;"></i> ENGINE SCANNING...';
                        btn.style.background = 'linear-gradient(135deg, #444, #666)';
                        btn.style.boxShadow = '0 0 15px rgba(255, 255, 255, 0.1)';
                        btn.classList.add('pulse-active');
                    } else {
                        btn.innerHTML = '<i class="ph-bold ph-rocket-launch" style="font-size: 22px;"></i> LAUNCH AUTONOMOUS SECURITY ARSENAL';
                        btn.style.background = 'linear-gradient(135deg, #ff6b6b, #ff8e53)';
                        btn.style.boxShadow = '0 4px 15px rgba(255, 107, 107, 0.3)';
                        btn.classList.remove('pulse-active');
                    }
                }

                if (progContainer) {
                    progContainer.style.display = data.is_scanning ? 'block' : 'none';
                    if (data.is_scanning && progStatus) {
                        progStatus.innerText = 'AUTONOMOUS PIPELINE IN PROGRESS...';
                    }
                }

                if (msg) {
                    msg.innerHTML = data.is_scanning ?
                        '<i class="ph ph-circle-notch animate-spin"></i> PIPELINE IN PROGRESS...' :
                        '<i class="ph ph-check-circle" style="color: #4dff88;"></i> Pipeline Idle';
                }

                loadData();
            }
        } catch (e) {}
    }, 4000);

    // Directory Picker Listener
    const picker = document.getElementById('directoryPicker');
    if (picker) {
        picker.onchange = (e) => {
            if (e.target.files.length > 0) {
                const folder = e.target.files[0].webkitRelativePath.split('/')[0];
                const targetInput = document.getElementById('scanTarget');
                if (targetInput) targetInput.value = `./${folder}`;
            }
        };
    }

    toggleAIField();
});
