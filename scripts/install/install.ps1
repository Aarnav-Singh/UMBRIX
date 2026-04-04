<#
.SYNOPSIS
UMBRIX Installation Script for Windows

.DESCRIPTION
This script checks for Docker, provisions a secure .env.prod file with random
generated credentials, and launches the entire UMBRIX infrastructure stack locally.
#>

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "    UMBRIX Command Center - Interactive Installer       " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Check Dependencies
$dockerExists = Get-Command docker -ErrorAction Ignore
if (-not $dockerExists) {
    Write-Host "[!] Docker is not installed. Please install Docker Desktop first: https://docs.docker.com/desktop/windows/install/" -ForegroundColor Red
    exit 1
}

$dockerComposeCmd = ""
# Check if 'docker compose' exists
$composeInfo = docker compose version 2>&1
if ($LASTEXITCODE -eq 0) {
    $dockerComposeCmd = "docker compose"
} else {
    # Check if older docker-compose exists
    $composeOld = Get-Command docker-compose -ErrorAction Ignore
    if ($composeOld) {
        $dockerComposeCmd = "docker-compose"
    } else {
        Write-Host "[!] Docker Compose is not installed or available." -ForegroundColor Red
        exit 1
    }
}

Write-Host "[✓] Docker and Docker Compose detected." -ForegroundColor Green

# 2. Setup Environment Variables
$envFile = ".env.prod"
if (-not (Test-Path -Path $envFile)) {
    Write-Host "[*] Generating secure environment variables..." -ForegroundColor Yellow
    
    $exampleFile = ".env.prod.example"
    if (-not (Test-Path -Path $exampleFile)) {
        Write-Host "[!] .env.prod.example not found in current directory. Are you in the UMBRIX root folder?" -ForegroundColor Red
        exit 1
    }
    
    Copy-Item -Path $exampleFile -Destination $envFile
    
    # Helper to generate random string
    function Get-RandomString($length) {
        $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        return -join (1..$length | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
    }

    $jwtSecret = Get-RandomString 64
    $pgPass = Get-RandomString 16
    $redisPass = Get-RandomString 16
    $chPass = Get-RandomString 16
    $gfPass = Get-RandomString 16
    
    # Replace contents in file
    $content = Get-Content -Path $envFile -Raw
    $content = $content -replace 'CHANGE_ME_STRONG_RANDOM_HEX_64_CHARS', $jwtSecret
    $content = $content -replace 'CHANGE_ME_STRONG_POSTGRES_PASSWORD', $pgPass
    $content = $content -replace 'CHANGE_ME_REDIS_PASSWORD', $redisPass
    $content = $content -replace 'CHANGE_ME_CLICKHOUSE_PASSWORD', $chPass
    $content = $content -replace 'CHANGE_ME_GRAFANA_ADMIN_PASSWORD', $gfPass
    
    Set-Content -Path $envFile -Value $content -Encoding UTF8
    
    Write-Host "[✓] Secure .env.prod generated." -ForegroundColor Green
    Write-Host ""
    Write-Host "    IMPORTANT: Your generated Administrator Grafana Password is: $gfPass" -ForegroundColor Magenta
    Write-Host "    Save this somewhere safe! You can also find it in the .env.prod file." -ForegroundColor Magenta
    Write-Host ""
} else {
    Write-Host "[✓] Existing $envFile found. Skipping credentials generation." -ForegroundColor Green
}

# 3. Booting up
Write-Host "[*] Booting UMBRIX infrastructure..." -ForegroundColor Yellow

if ($dockerComposeCmd -eq "docker compose") {
    docker compose -f docker-compose.prod.yml --env-file $envFile up -d --build
} else {
    docker-compose -f docker-compose.prod.yml --env-file $envFile up -d --build
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "    Installation Complete!                                " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "    Frontend:   http://localhost:3000                     "
Write-Host "    FastAPI:    http://localhost:8000/docs                "
Write-Host "    Grafana:    http://localhost:3001                     "
Write-Host "==========================================================" -ForegroundColor Cyan
