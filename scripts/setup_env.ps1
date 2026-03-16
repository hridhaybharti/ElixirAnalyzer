param(
  [switch]$RunTests
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Write-Host "Setting up ElixirAnalyzer in $root"

# Ensure Python is available
$pythonCmd = if (Get-Command python -ErrorAction SilentlyContinue) { "python" } elseif (Get-Command py -ErrorAction SilentlyContinue) { "py" } else { Write-Error "Python not found on PATH"; exit 1 }

# Create virtual environment if missing
$venv = Join-Path $root ".venv"
if (-Not (Test-Path $venv)) {
  & $pythonCmd -m venv $venv
}

# Activate venv if possible
$activatePath = Join-Path $venv "Scripts\Activate.ps1"
if (Test-Path $activatePath) {
  & $activatePath
} else {
  Write-Warning "Activate.ps1 not found; proceeding without activation"
}

# Install Python requirements
$pip = Join-Path $venv "Scripts\pip.exe"
if (-Not (Test-Path $pip)) { $pip = "pip" }
if (Test-Path (Join-Path $root "requirements.txt")) {
  & $pip install -r (Join-Path $root "requirements.txt")
}

# Install Node dependencies in root and frontend if present
if (Test-Path (Join-Path $root "package.json")) {
  npm install --prefix $root
}
 if (Test-Path (Join-Path (Join-Path $root "frontend") "package.json")) {
  npm install --prefix (Join-Path $root "frontend")
 }
 # Ensure Python test runner is installed in the virtual environment
 $py_exe = Join-Path $venv "Scripts\\python.exe"
 if (Test-Path $py_exe) {
  & $py_exe -m pip install pytest pytest-asyncio
}

Write-Host "Setup complete."
if ($RunTests) {
  Write-Host "Running Python tests..."
  & (Join-Path $venv "Scripts\python.exe") -m pytest -q
  if (Test-Path (Join-Path $root "frontend")) {
    Write-Host "Running frontend tests (if configured)..."
    npm test --prefix (Join-Path $root "frontend")
  }
}
