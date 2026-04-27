#!/usr/bin/env bash
# AegisFlow - macOS Quick Launch Script

set -u

COMPOSE_CMD=(docker compose)
DASHBOARD_URL="http://localhost:58081"
WAIT_TIMEOUT_SECONDS=90
WAIT_INTERVAL_SECONDS=2

print_error() {
    echo "❌ $1" >&2
}

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        print_error "Required command not found: $1"
        exit 1
    fi
}

preflight_docker() {
    require_command docker
    require_command curl

    if ! docker info >/dev/null 2>&1; then
        print_error "Docker daemon is not running."
        echo "💡 Open Docker Desktop and wait until it reports 'Engine running', then rerun this script."
        exit 1
    fi
}

wait_for_dashboard() {
    local elapsed=0

    echo "⏳ Waiting for Dashboard to initialize..."
    while (( elapsed < WAIT_TIMEOUT_SECONDS )); do
        if curl --output /dev/null --silent --head --fail "$DASHBOARD_URL"; then
            echo
            return 0
        fi

        printf '.'
        sleep "$WAIT_INTERVAL_SECONDS"
        elapsed=$((elapsed + WAIT_INTERVAL_SECONDS))
    done

    echo
    print_error "Dashboard did not become ready within ${WAIT_TIMEOUT_SECONDS}s."
    echo "💡 Check container status with: docker compose ps"
    echo "💡 Check AegisFlow logs with: docker compose logs aegisflow"
    return 1
}

echo "🚀 Starting AegisFlow Enterprise Hub for macOS..."
preflight_docker

# 1. Clean up old containers
echo "🧹 Cleaning up environment..."
if ! "${COMPOSE_CMD[@]}" down; then
    print_error "Failed to clean up existing containers."
    exit 1
fi

# 2. Build and start services in background
echo "📦 Building and starting services (this might take a minute)..."
if ! "${COMPOSE_CMD[@]}" up -d --build; then
    print_error "Failed to build and start services."
    exit 1
fi

# 3. Wait for the server to be ready
if ! wait_for_dashboard; then
    exit 1
fi

echo -e "\n✅ AegisFlow is UP and RUNNING!"

# 4. Automatically open the Dashboard in the default browser
echo "🌐 Opening Command Center..."
open "$DASHBOARD_URL"

# 5. Show logs for transparency
echo "📋 Showing real-time logs (Press Ctrl+C to exit logs, framework will keep running):"
"${COMPOSE_CMD[@]}" logs -f aegisflow
