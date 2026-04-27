# AegisFlow - Windows Quick Launch Script (PowerShell)

Write-Host "🚀 Starting AegisFlow Enterprise Hub for Windows..." -ForegroundColor Cyan

# 1. Clean up old containers
Write-Host "🧹 Cleaning up environment..." -ForegroundColor Yellow
docker-compose down

# 2. Build and start services
Write-Host "📦 Building and starting services..." -ForegroundColor Green
docker-compose up -d --build

# 3. Wait for the server
Write-Host "⏳ Waiting for Dashboard to initialize..." -ForegroundColor Cyan
while (!(Test-NetConnection -ComputerName localhost -Port 58081).TcpTestSucceeded) {
    Write-Host "." -NoNewline
    Start-Sleep -Seconds 2
}

Write-Host "\n✅ AegisFlow is UP and RUNNING!" -ForegroundColor Green

# 4. Open Browser
Write-Host "🌐 Opening Command Center..." -ForegroundColor Cyan
Start-Process "http://localhost:58081"

# 5. Show logs
Write-Host "📋 Showing real-time logs (Press Ctrl+C to exit):"
docker-compose logs -f aegisflow
