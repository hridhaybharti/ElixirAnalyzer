# Setup Instructions

This guide helps you bootstrap the development environment and run tests.

Prerequisites:
- Windows with PowerShell
- Python 3.11+ and npm/node

Steps:
1. Create a terminal in the repo root.
2. Run the bootstrap script:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup_env.ps1
```
3. If you want to run tests automatically after install:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup_env.ps1 -RunTests
```
4. For CI, rely on the GitHub Actions workflow in `.github/workflows/ci.yml`.

Shim mapping notes are in `docs/SHIMS_MAP.md`.