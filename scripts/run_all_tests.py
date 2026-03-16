#!/usr/bin/env python3
import sys
import subprocess

def main():
    # Run all tests with pytest in quiet mode; rely on local env
    cmd = [sys.executable, "-m", "pytest", "-q"]
    result = subprocess.run(cmd)
    sys.exit(result.returncode)

if __name__ == "__main__":
    main()
