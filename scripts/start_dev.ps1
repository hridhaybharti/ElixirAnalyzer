param(
  [switch]$UseDocker
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $scriptDir

Write-Host "Starting local development for ElixirAnalyzer..." -ForegroundColor Green

function Test-CommandExists($cmd) {
  try { & $cmd --version > $null 2>&1; return $true } catch { return $false }
}

# Prefer Docker if available and requested
if ($UseDocker) {
  try {
    docker --version | Out-Null
    docker compose version | Out-Null
    Write-Host "Using Docker Compose to deploy the stack..."
    docker compose up -d
    Start-Sleep -Seconds 15
    docker compose ps
    try {
      $resp = Invoke-WebRequest -Uri http://localhost:5000/ -TimeoutSec 5
      Write-Host "App reachable via Docker at http://localhost:5000/ (status: $($resp.StatusCode))"
    } catch { Write-Host "Docker app health check failed; inspect logs with docker compose logs -f app" }
    exit 0
  } catch {
    Write-Warning "Docker not available or failed. Falling back to local server start."
  }
}

# Fallback: local server start via npm scripts
if (Test-Path (Join-Path $root "package.json")) {
  Write-Host "Found root package.json; attempting npm install and start..."
  npm ci
  $pkg = Get-Content (Join-Path $root "package.json" | Resolve-Path -Relative) | ConvertFrom-Json
  if ($pkg.scripts -and $pkg.scripts.start) {
    npm run start
  } elseif ($pkg.scripts -and $pkg.scripts.dev) {
    npm run dev
  } else {
    Write-Warning "No start script found in root package.json. Skipping local server start."
  }
} elseif (Test-Path (Join-Path (Join-Path $root "server") "package.json")) {
  Write-Host "Found server/package.json; attempting npm install and start..."
  Push-Location (Join-Path $root "server")
  npm ci
  $pkg = Get-Content (Join-Path (Resolve-Path .) "package.json" | Resolve-Path -Relative) | ConvertFrom-Json
  if ($pkg.scripts -and $pkg.scripts.start) {
    npm run start
  } elseif ($pkg.scripts -and $pkg.scripts.dev) {
    npm run dev
  } else {
    Write-Warning "No start script found in server/package.json. Skipping local server start."
  }
  Pop-Location
} elseif ((Test-Path (Join-Path $root "server")) -and (Test-Path "$root\server\index.ts")) {
  Write-Host "Attempting to run local TS server via ts-node if available..."
  if (Test-Path (Join-Path $root "node_modules/.bin/ts-node")) {
    & (Join-Path $root "node_modules/.bin/ts-node") (Join-Path $root "server/index.ts")
  } else {
    Write-Warning "ts-node not found. Please run 'npm install' in server to install dev dependencies, or configure a start script."
  }
} else {
  Write-Warning "No npm-based server found."
}

Write-Host "Dev start script finished or not applicable. Checking health..."
try {
  $resp = Invoke-WebRequest -Uri http://localhost:5000/ -TimeoutSec 5
  Write-Host "Health check OK: HTTP $($resp.StatusCode)" -ForegroundColor Green
} catch {
  Write-Warning "Health check could not reach port 5000. If you know your app uses a different port, adjust the health URL."
}
