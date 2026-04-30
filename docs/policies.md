# AegisFlow Security Policies & Governance

This document outlines the security governance framework enforced by the AegisFlow pipeline, specifically within the `policy_engine.py` stage.

## 1. Policy Enforcement Rules (The Quality Gate)
The pipeline acts as an automated security gatekeeper. It evaluates the `full_report_triaged.json` against the following strict rules:

- **Condition 1 (CRITICAL Block):** If `CRITICAL_COUNT > 0`, the pipeline is **BLOCKED** (Exit Code 1).
- **Condition 2 (HIGH Threshold Block):** If `HIGH_COUNT >= 2`, the pipeline is **BLOCKED** (Exit Code 1).
- **Condition 3 (Risk Momentum Warning):** If the total calculated Risk Weight (Critical=50, High=20, Medium=5, Low=1) exceeds 50, the pipeline issues a **WARNING** (Exit Code 0) but allows the build to proceed.
- **Default:** If none of the above are met, the pipeline **PASSES**.

## 2. Service Level Agreements (SLA) for Remediation
When a vulnerability is detected, the AI Triage engine assigns an SLA deadline based on severity:
- **CRITICAL:** 24 Hours to remediate.
- **HIGH:** 72 Hours to remediate.
- **MEDIUM:** 168 Hours (7 Days) to remediate.
- **LOW:** 720 Hours (30 Days) to remediate.

## 3. Exception Handling (Risk Acceptance)
In a real-world scenario, not all findings can be fixed immediately.
- **Process:** Developers can request an exception (Risk Acceptance) via the dashboard (simulated).
- **Approval:** Exceptions for HIGH/CRITICAL issues must be approved by the CISO or Lead AppSec Engineer.
- **Tracking:** Approved exceptions bypass the Policy Gate but remain in the Audit Log for compliance reviews.

## 4. Dashboard Views & Roles
- **CISO / Board of Directors:** Views the Executive Summary, overall Security Score (0-100), Policy Pass/Fail status, and Compliance Mappings (ISO27001, GDPR).
- **AppSec Engineers:** Views detailed pipeline step statuses, scanner raw logs, and oversees policy configurations.
- **Developers:** Focuses on the Findings List, specifically the "AI Remediation Plan" which provides exact copy-paste code fixes and explanations.
