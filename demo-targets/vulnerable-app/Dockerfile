# ============================================================
# Dockerfile – vulnerable-app
#
# ??  WARNING: This Dockerfile contains INTENTIONAL misconfigurations
#     for DevSecOps pipeline scanning demonstration ONLY.
#     DO NOT build this image for production use.
#
# Intentional misconfigurations:
#   [VULN-006] CKV_DOCKER_2  – No USER directive ? runs as root
#   [VULN-009] CKV_DOCKER_7  – No HEALTHCHECK directive
#   [VULN-010] CKV_DOCKER_1  – EXPOSE 22 (SSH port exposed)
#   [VULN-011] No .dockerignore ? secrets and tests copied into image
#   [VULN-012] Using 'latest' pinning strategy is risky (pinned to 18 here)
#   [VULN-013] npm install includes devDependencies in production image
# ============================================================

# Base image – Node 18 (unpinned digest – supply chain risk)
FROM node:18

# -------------------------------------------------------------
# [VULN-006] CKV_DOCKER_2 – CWE-250 – OWASP A05:2021
# VULNERABLE: No USER instruction – container runs as root (UID 0).
# If this container is compromised, the attacker has root access
# and can attempt container escape via kernel exploits.
#
# Fix:
#   RUN addgroup -S appgroup && adduser -S appuser -G appgroup
#   USER appuser
# -------------------------------------------------------------

# Working directory (owned by root – intentional)
WORKDIR /app

# -------------------------------------------------------------
# [VULN-011] No .dockerignore – copies entire project context
# including .env, secrets/, test/, coverage/, and .git/
# -------------------------------------------------------------
COPY . .

# Install ALL dependencies including devDependencies
# [VULN-013] Should use: npm install --production --omit=dev
RUN npm install

# -------------------------------------------------------------
# [VULN-010] CKV_DOCKER_1 – CWE-284
# VULNERABLE: Port 22 (SSH) is exposed.
# Containers should never expose SSH – use orchestrator exec instead.
# This widens the attack surface significantly.
# -------------------------------------------------------------
EXPOSE 22
EXPOSE 53000

# -------------------------------------------------------------
# [VULN-009] CKV_DOCKER_7 – CWE-778
# VULNERABLE: No HEALTHCHECK defined.
# The orchestrator cannot detect if the application crashes
# or enters a hung/unhealthy state.
#
# Fix:
#   HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
#     CMD curl -f http://localhost:53000/ || exit 1
# -------------------------------------------------------------

# Start the application as root
CMD ["node", "app.js"]
