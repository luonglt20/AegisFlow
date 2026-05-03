// AegisFlow - Unified Enterprise Security Dashboard Logic
// Built for AppSec Excellence & Task 1-5 Compliance

const appState = {
    data: {
        findings: [],
        policy: {},
        quality: {},
        sbom: {},
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
    const normalized = String(statusLabel).toUpperCase();
    const isBlocked = normalized === 'BLOCKED' || normalized === 'FAILED';

    return {
        ...payload,
        passed: payload.passed ?? !isBlocked,
        statusLabel,
        quality_summary: payload.quality_summary || {}
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
    const status = appState.data.status || {};

    // Determine the most accurate app name available
    const appName = meta.app_name || 
                    meta.target_name || 
                    (status.target ? status.target.split('/').pop() : '') ||
                    (appState.lastTarget ? appState.lastTarget.split('/').pop() : '') || 
                    'Not selected';
    
    const scanId = meta.pipeline_run_id || meta.scan_id || (status.is_scanning ? 'SCANNING...' : 'N/A');
    const branch = meta.branch || 'main';
    const scanTime = meta.scan_timestamp || meta.generated_at || meta.scan_date || meta.timestamp || (status.is_scanning ? 'Active Scan' : 'N/A');

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

        const [findingsPayload, policyPayload, auditPayload, statusPayload, buildPayload, testPayload, sbomPayload] = await Promise.all([
            fetchJsonWithFallback([
                `/data/full_report_triaged.json?v=${timestamp}`,
                `/data/full_report.json?v=${timestamp}`
            ], { findings: [] }),
            fetchJsonWithFallback([`/data/policy_result.json?v=${timestamp}`], {}),
            fetchJsonWithFallback([`/data/audit_log.json?v=${timestamp}`], []),
            fetchJsonWithFallback([`/api/status?v=${timestamp}`], {}),
            fetchJsonWithFallback([`/data/build_report.json?v=${timestamp}`], {}),
            fetchJsonWithFallback([`/data/test_report.json?v=${timestamp}`], {}),
            fetchJsonWithFallback([`/data/sbom.json?v=${timestamp}`], {})
        ]);

        appState.data.findings = normalizeFindings(findingsPayload);
        appState.data.policy = normalizePolicy(policyPayload);
        appState.data.audit = normalizeAudit(auditPayload);
        appState.data.status = statusPayload;
        appState.data.quality = {
            build: buildPayload?.stage ? buildPayload : policyPayload?.quality_summary?.build || {},
            test: testPayload?.stage ? testPayload : policyPayload?.quality_summary?.test || {}
        };
        appState.data.sbom = sbomPayload || {};
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
    renderPipelineStatus();
    renderSbom();
    updateStatusChrome();

    updateScanMeta(appState.data.scanMeta);
}

function getPolicyStatus() {
    const status = String(appState.data.policy?.pipeline_status || appState.data.policy?.statusLabel || 'UNKNOWN').toUpperCase();
    return status === 'INITIALIZED' ? 'UNKNOWN' : status;
}

function statusBadgeClass(status) {
    const normalized = String(status || '').toUpperCase();
    if (normalized === 'PASSED' || normalized === 'COMPLETED' || normalized === 'PASS') return 'badge-low';
    if (normalized === 'WARNING' || normalized === 'SKIPPED' || normalized === 'FALLBACK' || normalized === 'VALIDATION') return 'badge-medium';
    if (normalized === 'BLOCKED' || normalized === 'FAILED' || normalized === 'FAIL') return 'badge-critical';
    if (normalized === 'RUNNING') return 'badge-brand';
    return 'badge-outline';
}

function updateStatusChrome() {
    const policyStatus = getPolicyStatus();
    const policy = appState.data.policy || {};
    const status = appState.data.status || {};
    const topStatus = document.getElementById('top-status-badge');
    const topMode = document.getElementById('top-mode-badge');
    const sidebarDot = document.getElementById('sidebar-policy-dot');
    const sidebarLabel = document.getElementById('sidebar-policy-label');

    const label = status.is_scanning ? 'Running' : policyStatus === 'UNKNOWN' ? 'No Scan' : policyStatus;
    if (topStatus) {
        topStatus.className = `badge ${statusBadgeClass(status.is_scanning ? 'RUNNING' : policyStatus)}`;
        topStatus.textContent = label;
    }
    if (topMode) {
        const strict = policy.strict_ci ? 'Strict CI' : 'Evidence mode';
        topMode.className = 'badge badge-outline';
        topMode.textContent = strict;
    }
    if (sidebarDot) {
        sidebarDot.classList.toggle('blink', status.is_scanning || policyStatus === 'BLOCKED');
        sidebarDot.style.background = policyStatus === 'BLOCKED' || policyStatus === 'FAILED'
            ? 'var(--sev-critical)'
            : policyStatus === 'WARNING'
                ? 'var(--sev-medium)'
                : policyStatus === 'PASSED'
                    ? 'var(--sev-low)'
                    : 'var(--text-muted)';
    }
    if (sidebarLabel) sidebarLabel.textContent = status.is_scanning ? 'Pipeline running' : label;
}

function renderReportPreview() {
    const preview = document.getElementById('report-preview');
    if (!preview) return;

    const findings = appState.data.findings || [];
    const meta = appState.data.scanMeta || {};
    const stats = appState.data.status || {};

    const criticals = findings.filter(f => f.severity === 'CRITICAL');
    const highs = findings.filter(f => f.severity === 'HIGH');

    // Group findings by scan type
    const grouped = findings.reduce((acc, f) => {
        const type = (f.scan_type || 'OTHER').toUpperCase();
        if (!acc[type]) acc[type] = [];
        acc[type].push(f);
        return acc;
    }, {});

    const getIcon = (t) => {
        if (t === 'SAST') return 'ph-code';
        if (t === 'SCA') return 'ph-package';
        if (t === 'DAST') return 'ph-globe';
        if (t === 'IAC') return 'ph-cloud-check';
        if (t === 'SECRET') return 'ph-key';
        return 'ph-shield';
    };

    preview.innerHTML = `
        <div class="report-document" style="max-width: 900px; margin: 0 auto; color: #1e293b; line-height: 1.6; font-family: 'Inter', sans-serif; background: #fff; padding: 10px;">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 4px solid #ff6b00; padding-bottom: 24px; margin-bottom: 40px;">
                <div>
                    <h1 style="color: #ff6b00; font-size: 32px; margin: 0 0 8px 0; font-weight: 800; letter-spacing: -1px;">SECURITY ASSESSMENT</h1>
                    <div style="font-size: 14px; color: #64748b; font-weight: 600; text-transform: uppercase;">
                        Report ID: ${meta.pipeline_run_id || 'AF-' + Math.random().toString(36).substr(2, 6).toUpperCase()}
                    </div>
                </div>
                <div style="text-align: right;">
                    <div style="font-weight: 900; font-size: 20px; color: #0f172a;">AEGISFLOW ENTERPRISE</div>
                    <div style="font-size: 14px; color: #64748b;">Generated: ${new Date().toLocaleDateString()}</div>
                </div>
            </div>

            <section style="margin-bottom: 48px;">
                <h2 style="font-size: 20px; color: #0f172a; border-left: 5px solid #ff6b00; padding-left: 15px; margin-bottom: 24px; font-weight: 800; text-transform: uppercase;">1. Executive Summary</h2>
                <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 16px; padding: 32px;">
                    <p style="font-size: 16px; color: #334155; margin-bottom: 32px;">
                        Automated assessment for <span style="color: #ff6b00; font-weight: 700;">${meta.app_name || 'Autonomous Target'}</span>.
                    </p>
                    <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 24px;">
                        <div style="background: #fff; border: 1px solid #e2e8f0; padding: 20px; border-radius: 12px; text-align: center;">
                            <div style="font-size: 11px; font-weight: 800; color: #64748b; margin-bottom: 8px;">Security Score</div>
                            <div style="font-size: 32px; font-weight: 900; color: ${(stats.security_score || 0) < 70 ? '#ef4444' : '#10b981'};">${stats.security_score || '--'}</div>
                        </div>
                        <div style="background: #fff; border: 1px solid #fee2e2; padding: 20px; border-radius: 12px; text-align: center;">
                            <div style="font-size: 11px; font-weight: 800; color: #991b1b; margin-bottom: 8px;">Critical Risks</div>
                            <div style="font-size: 32px; font-weight: 900; color: #ef4444;">${criticals.length}</div>
                        </div>
                        <div style="background: #fff; border: 1px solid #ffedd5; padding: 20px; border-radius: 12px; text-align: center;">
                            <div style="font-size: 11px; font-weight: 800; color: #9a3412; margin-bottom: 8px;">High Risks</div>
                            <div style="font-size: 32px; font-weight: 900; color: #f97316;">${highs.length}</div>
                        </div>
                    </div>
                </div>
            </section>

            <section style="margin-bottom: 48px;">
                <h2 style="font-size: 20px; color: #0f172a; border-left: 5px solid #ff6b00; padding-left: 15px; margin-bottom: 24px; font-weight: 800; text-transform: uppercase;">2. Detailed Analysis by Layer</h2>
                ${Object.keys(grouped).length === 0 ? '<p style="color: #64748b; text-align: center; padding: 40px; background: #f8fafc; border-radius: 12px;">No findings detected in any layer.</p>' : ''}
                
                ${Object.entries(grouped).map(([type, list]) => `
                    <div style="margin-bottom: 32px; border: 1px solid #e2e8f0; border-radius: 12px; overflow: hidden;">
                        <div style="background: #f1f5f9; padding: 12px 20px; border-bottom: 1px solid #e2e8f0; display: flex; align-items: center; gap: 10px;">
                            <i class="ph-bold ${getIcon(type)}" style="font-size: 18px; color: #ff6b00;"></i>
                            <span style="font-weight: 800; font-size: 14px; color: #334155;">${type} Analysis - ${list.length} Findings</span>
                        </div>
                        <div style="padding: 0;">
                            <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
                                <thead style="background: #f8fafc;">
                                    <tr>
                                        <th style="padding: 12px 20px; text-align: left; border-bottom: 1px solid #f1f5f9; width: 100px;">Severity</th>
                                        <th style="padding: 12px 20px; text-align: left; border-bottom: 1px solid #f1f5f9;">Finding Details</th>
                                        <th style="padding: 12px 20px; text-align: left; border-bottom: 1px solid #f1f5f9;">Remediation Hint</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${list.map(f => `
                                        <tr>
                                            <td style="padding: 16px 20px; vertical-align: top; border-bottom: 1px solid #f1f5f9;">
                                                <span style="background: ${f.severity === 'CRITICAL' ? '#fee2e2' : f.severity === 'HIGH' ? '#ffedd5' : '#f1f5f9'}; color: ${f.severity === 'CRITICAL' ? '#991b1b' : f.severity === 'HIGH' ? '#9a3412' : '#475569'}; padding: 4px 8px; border-radius: 4px; font-weight: 700; font-size: 10px;">${f.severity}</span>
                                            </td>
                                            <td style="padding: 16px 20px; vertical-align: top; border-bottom: 1px solid #f1f5f9;">
                                                <div style="font-weight: 700; color: #0f172a; margin-bottom: 4px;">${escapeHtml(f.title)}</div>
                                                <div style="font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #64748b; margin-bottom: 8px;">${escapeHtml(formatPathWithLine(f))}</div>
                                                <div style="background: #fafafa; border: 1px solid #f0f0f0; border-radius: 6px; padding: 10px; font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #444; white-space: pre-wrap; overflow-x: auto;">${escapeHtml(JSON.stringify(f.evidence || f.description || {}, null, 2))}</div>
                                            </td>
                                            <td style="padding: 16px 20px; vertical-align: top; border-bottom: 1px solid #f1f5f9;">
                                                <div style="color: #334155; font-size: 12px;">${escapeHtml(f.remediation_hint || 'Contact security team for fix.')}</div>
                                            </td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                    </div>
                `).join('')}
            </section>
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
            <div style="margin-top: 16px;">
                <div class="code-container" style="margin-bottom: 0;">
                    <div class="code-container-header">
                        <div class="code-window-controls">
                            <div class="code-window-dot dot-red"></div>
                            <div class="code-window-dot dot-yellow"></div>
                            <div class="code-window-dot dot-green"></div>
                        </div>
                        <div class="code-window-title">Suggested Fix / Remediation</div>
                        <div></div>
                    </div>
                    <pre class="code-block code-after" style="padding: 16px;">${escapeHtml(fix.after)}</pre>
                </div>
            </div>
        `);
    }

    return parts.join('');
}

function normalizeTargetPath(rawTarget) {
    if (!rawTarget) return '';

    let normalized = String(rawTarget).trim().replace(/\\/g, '/');

    // Handle /real-apps/ paths (legacy)
    const marker = '/real-apps/';
    const markerIndex = normalized.lastIndexOf(marker);
    if (markerIndex >= 0) {
        normalized = `.${normalized.slice(markerIndex)}`;
    }

    // Handle /demo-targets/ paths (new structure)
    const demoMarker = '/demo-targets/';
    const demoMarkerIndex = normalized.lastIndexOf(demoMarker);
    if (demoMarkerIndex >= 0) {
        normalized = `.${normalized.slice(demoMarkerIndex)}`;
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

async function parseApiResponse(res) {
    let data = {};

    try {
        data = await res.json();
    } catch (err) {
        data = {};
    }

    if (!res.ok) {
        throw new Error(data.error || `Request failed with status ${res.status}.`);
    }

    return data;
}

function openProjectBrowser() {
    const modal = document.getElementById('project-modal');
    if (modal) {
        modal.style.display = 'flex';
        requestAnimationFrame(() => modal.classList.add('open'));
    }
}

function closeProjectBrowser() {
    const modal = document.getElementById('project-modal');
    if (modal) {
        modal.classList.remove('open');
        setTimeout(() => { modal.style.display = 'none'; }, 180);
    }
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
        ['File Path', formatPathWithLine(finding)],
        ['CVSS Score', formatCvss(finding)],
        ['EPSS Rating', finding.epss_score ?? 'N/A'],
        ['MITRE Framework', formatMitre(finding)],
        ['Compliance Standard', finding.compliance_controls || 'N/A'],
        ['Remediation SLA', finding.sla_deadline || 'N/A']
    ];

    return `
        <div style="display: grid; grid-template-columns: 1.3fr 1fr; gap: 24px;">
            <!-- Left Column: Description & Metadata -->
            <div class="glass-card" style="padding: 24px; background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.08);">
                <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 16px;">
                    <div style="width: 32px; height: 32px; border-radius: 8px; background: rgba(99, 102, 241, 0.1); display: flex; align-items: center; justify-content: center;">
                        <i class="ph ph-info" style="color: #818cf8; font-size: 18px;"></i>
                    </div>
                    <h5 style="margin: 0; font-size: 14px; font-weight: 600; color: var(--text-main); letter-spacing: 0.3px;">Description & Security Impact</h5>
                </div>
                
                <p style="font-size: 14px; color: var(--text-muted); margin-bottom: 20px; line-height: 1.7; font-weight: 400;">
                    ${escapeHtml(finding.business_impact || finding.impact || finding.description || 'No detailed impact analysis available.')}
                </p>

                <div style="display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 24px;">
                    ${metadata.map(label => `<span class="badge badge-outline" style="padding: 4px 10px; border-color: rgba(255,255,255,0.1); background: rgba(255,255,255,0.02); color: var(--text-muted); font-weight: 500;">${escapeHtml(label)}</span>`).join('')}
                </div>

                <div style="display: grid; grid-template-columns: 160px 1fr; gap: 12px 16px; font-size: 13px; border-top: 1px solid rgba(255,255,255,0.06); padding-top: 20px;">
                    ${references.map(([label, value]) => `
                        <div style="color: var(--text-muted); font-weight: 500;">${escapeHtml(label)}</div>
                        <div style="color: var(--text-main); font-family: 'JetBrains Mono', monospace; font-size: 12px;">${escapeHtml(value)}</div>
                    `).join('')}
                </div>
            </div>

            <!-- Right Column: AI Remediation -->
            <div class="glass-card" style="padding: 24px; background: linear-gradient(135deg, rgba(16, 185, 129, 0.03), rgba(5, 150, 105, 0.08)); border: 1px solid rgba(16, 185, 129, 0.15);">
                <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 16px;">
                    <div style="width: 32px; height: 32px; border-radius: 8px; background: rgba(16, 185, 129, 0.1); display: flex; align-items: center; justify-content: center;">
                        <i class="ph ph-magic-wand" style="color: #34d399; font-size: 18px;"></i>
                    </div>
                    <h5 style="margin: 0; font-size: 14px; font-weight: 600; color: #34d399; letter-spacing: 0.3px;">Autonomous Remediation Plan</h5>
                </div>
                
                <div style="font-size: 14px; color: #a7f3d0; line-height: 1.7;">
                    <div style="margin-bottom: 16px; padding: 12px; background: rgba(16, 185, 129, 0.05); border-radius: 6px; border-left: 3px solid #10b981;">
                        ${escapeHtml(finding.remediation_hint || finding.remediation || 'Consult security documentation for remediation steps.')}
                    </div>
                    ${formatAiFix(finding)}
                </div>
            </div>
        </div>

        ${(finding.ai_analysis || evidence) ? `
            <div style="margin-top: 24px; display: grid; grid-template-columns: 1fr 1fr; gap: 24px;">
                <!-- AI Triage Analysis -->
                <div class="glass-card" style="padding: 24px; background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.08);">
                    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 16px;">
                        <div style="width: 32px; height: 32px; border-radius: 8px; background: rgba(129, 140, 248, 0.1); display: flex; align-items: center; justify-content: center;">
                            <i class="ph ph-robot" style="color: #818cf8; font-size: 18px;"></i>
                        </div>
                        <h5 style="margin: 0; font-size: 14px; font-weight: 600; color: var(--text-main);">AI Triage Logic</h5>
                    </div>
                    <p style="font-size: 14px; color: var(--text-muted); line-height: 1.7; margin: 0; font-style: italic;">
                        "${escapeHtml(finding.ai_analysis || 'AI is performing contextual analysis on this finding...')}"
                    </p>
                </div>

                <!-- Code Evidence -->
                <div class="glass-card" style="padding: 24px; background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.08);">
                    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 16px;">
                        <div style="width: 32px; height: 32px; border-radius: 8px; background: rgba(244, 63, 94, 0.1); display: flex; align-items: center; justify-content: center;">
                            <i class="ph ph-code" style="color: #fb7185; font-size: 18px;"></i>
                        </div>
                        <h5 style="margin: 0; font-size: 14px; font-weight: 600; color: var(--text-main);">Vulnerable Evidence</h5>
                    </div>
                    
                    <div class="code-container" style="margin-bottom: 0; border: 1px solid rgba(255,255,255,0.08); background: rgba(0,0,0,0.3);">
                        <div class="code-container-header" style="background: rgba(255,255,255,0.03); border-bottom: 1px solid rgba(255,255,255,0.05);">
                            <div class="code-window-controls">
                                <div class="code-window-dot dot-red"></div>
                                <div class="code-window-dot dot-yellow"></div>
                                <div class="code-window-dot dot-green"></div>
                            </div>
                            <div class="code-window-title" style="font-size: 10px; color: var(--text-muted);">Source Context</div>
                            <div></div>
                        </div>
                        <pre class="code-block code-before" style="padding: 16px; font-size: 12px; line-height: 1.6; color: #fecdd3;">${escapeHtml(evidence || 'No code evidence available for this finding.')}</pre>
                    </div>
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

    const critEl = document.getElementById('kpi-critical');
    if (critEl) critEl.innerText = s.critical;
    const critLabel = document.getElementById('kpi-critical-label');
    if (critLabel) critLabel.innerText = s.critical > 0 ? 'Action required' : 'No critical findings';

    const quality = appState.data.quality || {};
    const qualityStatuses = [quality.build?.status, quality.test?.status].filter(Boolean);
    const failedQuality = qualityStatuses.filter(v => v === 'failed').length;
    const skippedQuality = qualityStatuses.filter(v => v === 'skipped').length;
    const qualityEl = document.getElementById('kpi-quality');
    const qualityLabel = document.getElementById('kpi-quality-label');
    if (qualityEl) {
        qualityEl.innerText = failedQuality ? 'FAIL' : skippedQuality ? 'SKIP' : qualityStatuses.length ? 'PASS' : '--';
        qualityEl.style.color = failedQuality ? 'var(--sev-critical)' : skippedQuality ? 'var(--sev-medium)' : 'var(--sev-low)';
    }
    if (qualityLabel) qualityLabel.innerText = `${quality.build?.mode || 'build?'} / ${quality.test?.mode || 'test?'}`;

    const totalEl = document.getElementById('kpi-total');
    const totalLabel = document.getElementById('kpi-total-label');
    if (totalEl) totalEl.innerText = s.total;
    if (totalLabel) totalLabel.innerText = `${s.high} high, ${s.medium} medium, ${s.low} low`;
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
        'build': 'build-status',
        'test': 'test-status',
        'sast': 'sast-status',
        'sca': 'sca-status',
        'secret': 'secret-status',
        'sbom': 'sbom-status',
        'iac': 'iac-status',
        'dast': 'dast-status',
        'api': 'api-status',
        'policy': 'policy-status'
    };

    Object.keys(mapping).forEach(key => {
        const el = document.getElementById(mapping[key]);
        if (!el) return;
        const state = status[key] || 'pending';
        if (state === 'running') el.innerHTML = '<i class="ph ph-circle-notch animate-spin" style="color: var(--brand-primary);"></i>';
        else if (state === 'completed' || state === 'passed') el.innerHTML = '<i class="ph ph-check-circle" style="color: var(--sev-low);"></i>';
        else if (state === 'failed') el.innerHTML = '<i class="ph ph-x-circle" style="color: var(--sev-critical);"></i>';
        else el.innerHTML = '<i class="ph ph-circle" style="color: #94a3b8;"></i>';
    });
}

function updateKPIs() {
    const gateEl = document.getElementById('kpi-gate');
    if (gateEl) {
        const passed = appState.data.policy.passed !== false;
        gateEl.innerText = appState.data.policy.statusLabel || (passed ? "PASSED" : "FAIL");
        gateEl.style.color = passed ? 'var(--sev-low)' : 'var(--sev-critical)';
    }

    const mttd = document.getElementById('kpi-mttd');
    const mttr = document.getElementById('kpi-mttr');
    const ver = document.getElementById('kpi-ver');
    if (mttd) mttd.innerText = "1.2h";
    if (mttr) mttr.innerText = "4.5h";
    if (ver) ver.innerText = "0.5%";
}

function stageLabel(stage) {
    const status = stage?.status || 'unknown';
    const mode = stage?.mode || 'unknown';
    return `${status}${mode && mode !== status ? ` · ${mode}` : ''}`;
}

function renderPipelineStatus() {
    const title = document.getElementById('pipeline-title');
    const reason = document.getElementById('pipeline-reason');
    const grid = document.getElementById('pipeline-stage-grid');
    const policy = appState.data.policy || {};
    const status = appState.data.status || {};
    const quality = appState.data.quality || {};
    const policyStatus = status.is_scanning ? 'RUNNING' : getPolicyStatus();

    if (title) {
        title.textContent = policyStatus === 'UNKNOWN' ? 'Pipeline Status' : `Pipeline ${policyStatus}`;
        title.style.color = policyStatus === 'BLOCKED' || policyStatus === 'FAILED' ? 'var(--sev-critical)' : policyStatus === 'WARNING' ? 'var(--sev-medium)' : 'var(--sev-low)';
    }
    if (reason) reason.textContent = policy.block_reason || 'Run a scan to evaluate build, test, security, policy, audit, and report gates.';
    if (!grid) return;

    const stages = [
        ['Build', stageLabel(quality.build || { status: status.build })],
        ['Test', stageLabel(quality.test || { status: status.test })],
        ['SAST', status.sast || 'pending'],
        ['SCA', status.sca || 'pending'],
        ['Secrets', status.secret || 'pending'],
        ['IaC', status.iac || 'pending'],
        ['DAST', status.dast || 'pending'],
        ['Policy', status.policy || policyStatus.toLowerCase()]
    ];

    grid.innerHTML = stages.map(([name, state]) => `
        <div class="stage-chip">
            <span>${escapeHtml(name)}</span>
            <span class="badge ${statusBadgeClass(state)}">${escapeHtml(state)}</span>
        </div>
    `).join('');
}

function renderSbom() {
    const target = document.getElementById('sbom-data');
    if (!target) return;
    const sbom = appState.data.sbom || {};
    if (!Object.keys(sbom).length) {
        target.textContent = 'No SBOM has been generated yet.';
        return;
    }
    const components = Array.isArray(sbom.components) ? sbom.components : [];
    const summary = {
        bomFormat: sbom.bomFormat,
        specVersion: sbom.specVersion,
        component_count: components.length,
        tool: sbom.metadata?.tools?.components?.[0]?.name || 'unknown',
        target: sbom.metadata?.component?.name || 'unknown'
    };
    target.textContent = JSON.stringify({ summary, sample_components: components.slice(0, 20) }, null, 2);
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

    container.innerHTML = filtered.map((f, index) => {
        const severity = String(f.severity || 'LOW').toUpperCase();
        const safeId = escapeHtml(f.id || `finding-${index}`);
        return `
        <div class="finding-card ${severity.toLowerCase()}" style="margin-bottom: 12px; background: rgba(255,255,255,0.02); border-radius: 8px; border: 1px solid var(--border-light); overflow: hidden; transition: all 0.2s;">
            <div class="finding-header" onclick="toggleDetails('${safeId}')" style="display: flex; align-items: center; padding: 16px; cursor: pointer;">
                <div style="flex: 1;">
                    <div style="display: flex; gap: 8px; margin-bottom: 8px;">
                        <span class="badge badge-${severity.toLowerCase()}" style="padding: 4px 8px; font-weight: 700; font-size: 10px;">${escapeHtml(severity)}</span>
                        ${f.status === 'AI_TRIAGED' ? '<span class="badge" style="background: rgba(245,158,11,0.1); color: #f59e0b; border: 1px solid rgba(245,158,11,0.3);"><i class="ph ph-sparkle" style="margin-right: 4px;"></i>AI TRIAGED</span>' : ''}
                        <span class="badge badge-outline" style="border-color: var(--border-light);">${escapeHtml(f.source_tool || f.tool || 'Engine')}</span>
                    </div>
                    <h4 style="margin: 0; font-size: 16px; color: var(--text-main); font-weight: 600;">${escapeHtml(f.title || 'Untitled finding')}</h4>
                    <div style="font-size: 12px; color: var(--text-muted); font-family: 'JetBrains Mono', monospace; margin-top: 6px;"><i class="ph ph-file-code" style="margin-right: 4px;"></i>${escapeHtml(formatPathWithLine(f))}</div>
                </div>
                <div style="text-align: right; margin-right: 20px;">
                    <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; margin-bottom: 4px;">CVSS Score</div>
                    <div style="font-size: 18px; font-weight: 800; color: var(--sev-${severity.toLowerCase()}); background: rgba(255,255,255,0.05); padding: 4px 12px; border-radius: 6px; border: 1px solid var(--sev-${severity.toLowerCase()}); display: inline-block;">${escapeHtml(formatCvss(f))}</div>
                </div>
                <div style="width: 32px; height: 32px; display: flex; align-items: center; justify-content: center; background: rgba(255,255,255,0.05); border-radius: 50%;">
                    <i class="ph ph-caret-down" id="icon-${safeId}" style="color: var(--text-muted); transition: transform 0.2s;"></i>
                </div>
            </div>
            <div id="details-${safeId}" class="finding-details" style="display: none; padding: 24px; border-top: 1px solid var(--border-light); background: rgba(0,0,0,0.2);">
                ${renderFindingDetails(f)}
            </div>
        </div>
    `}).join('');
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
    console.log("[UI] Launching evidence-based pipeline...");
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

    const allScanners = ['sast', 'sca', 'sbom', 'secret', 'iac', 'dast'];
    const enabledScanners = allScanners.filter(id => {
        const el = document.getElementById(`scanner-${id}`);
        return el ? el.checked : true;
    });

    // UI Feedback
    const btn = document.getElementById('launchBtn');
    const msg = document.getElementById('scan-status-msg');
    if (btn) btn.disabled = true;
    if (msg) msg.innerHTML = '<i class="ph ph-circle-notch animate-spin"></i> Pipeline launched...';
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
                groq_key: apiKey,
                scanners: enabledScanners
            })
        });

        const data = await parseApiResponse(res);
        console.log("[SERVER] Scan Status:", data);
        if (data.status === 'SCAN_STARTED') {
            appState.isScanning = true;
            loadData();
        }
    } catch (err) {
        console.error("[UI] Launch Failed:", err);
        if (btn) btn.disabled = false;
        if (msg) {
            msg.innerHTML = `<i class="ph ph-warning-circle" style="color: #f59e0b;"></i> ${escapeHtml(err.message || 'Launch Failed. Check Connection.')}`;
        }
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

function exportJSON() {
    if (!appState.data.findings || appState.data.findings.length === 0) {
        alert("No data available to export.");
        return;
    }
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(appState.data, null, 2));
    const downloadAnchorNode = document.createElement('a');
    downloadAnchorNode.setAttribute("href", dataStr);
    downloadAnchorNode.setAttribute("download", `aegisflow_report_${new Date().getTime()}.json`);
    document.body.appendChild(downloadAnchorNode);
    downloadAnchorNode.click();
    downloadAnchorNode.remove();
}

function printReport() {
    window.print();
}

function exportAuditCSV() {
    if (!appState.data.audit || appState.data.audit.length === 0) {
        alert("No audit logs available to export.");
        return;
    }
    const headers = ["Timestamp", "Actor", "Action", "Finding ID", "Detail"];
    const rows = appState.data.audit.map(a => [a.timestamp, a.actor, a.action, a.finding_id || '', a.detail]);

    let csvContent = "data:text/csv;charset=utf-8,"
        + headers.join(",") + "\n"
        + rows.map(e => e.join(",")).join("\n");

    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `aegisflow_audit_${new Date().getTime()}.csv`);
    document.body.appendChild(link);
    link.click();
    link.remove();
}

// ─── Initialization ──────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    loadData();

    // Polling Logic
    setInterval(async () => {
        try {
            const res = await fetch('/api/status');
            const data = await res.json();

            // Normalize is_scanning - guard against string "false" from pipeline
            const isScanning = data.is_scanning === true || data.is_scanning === 'true';

            // Detect state change from scanning -> idle
            const finishedScanning = appState.isScanning && !isScanning;

            // Update scanning state
            appState.isScanning = isScanning;
            data.is_scanning = isScanning; // normalize for downstream usage
            appState.data.status = data;

            const btn = document.getElementById('launchBtn');
            const msg = document.getElementById('scan-status-msg');
            const progContainer = document.getElementById('progress-container');
            const progStatus = document.getElementById('progress-status');

            if (btn) {
                btn.disabled = data.is_scanning;
                if (data.is_scanning) {
                    btn.innerHTML = '<i class="ph ph-circle-notch animate-spin" style="font-size: 22px;"></i> PIPELINE RUNNING...';
                    btn.style.background = 'linear-gradient(135deg, #444, #666)';
                    btn.classList.add('pulse-active');
                } else {
                    btn.innerHTML = '<i class="ph-bold ph-rocket-launch" style="font-size: 22px;"></i> RUN EVIDENCE-BASED SECURITY PIPELINE';
                    btn.style.background = 'linear-gradient(135deg, #ff6b00, #ff8c3a)';
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
                if (isScanning) {
                    msg.innerHTML = '<i class="ph ph-circle-notch animate-spin"></i> Pipeline in progress...';
                } else if (finishedScanning) {
                    msg.innerHTML = '<i class="ph ph-check-circle" style="color: var(--sev-low);"></i> Pipeline Finished';
                }
                // If not scanning and didn't just finish, we DON'T overwrite (keep errors visible)
            }

            // Always refresh if scanning (to show progress) or if we just finished (to show final results)
            if (data.is_scanning || finishedScanning) {
                loadData();
            }
        } catch (e) { }
    }, 3000);

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
