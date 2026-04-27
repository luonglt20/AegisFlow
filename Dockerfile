FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    wget \
    unzip \
    nodejs \
    npm \
    golang \
    && rm -rf /var/lib/apt/lists/*

# Install Python-based security tools
RUN pip install --no-cache-dir semgrep checkov requests

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install Gitleaks
RUN curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz | tar -xz -C /usr/local/bin gitleaks

# Install Syft
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# 7. Install Nuclei (DAST) via Go and Pre-install templates
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    ln -s /root/go/bin/nuclei /usr/local/bin/nuclei && \
    nuclei -update-templates

# Copy project files
COPY . .

ENV PYTHONUNBUFFERED=1
ENV SCAN_TARGET=/app/real-apps/NodeGoat
ENV PORT=58081

EXPOSE 58081

CMD ["python3", "server.py"]
