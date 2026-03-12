"""pytest configuration: map backend -> legacy_python_research for backward compatibility."""

import sys
import os
import pytest

# Add project root to path
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Create a module alias so 'backend' imports work
import legacy_python_research as backend
sys.modules['backend'] = backend

# Sub-module aliases
sys.modules['backend.analyzers'] = backend.analyzers
sys.modules['backend.core'] = backend.core
sys.modules['backend.heuristics'] = backend.heuristics
sys.modules['backend.utils'] = backend.utils
sys.modules['backend.api'] = backend.api
sys.modules['backend.persistence'] = backend.persistence

# Register asyncio marker
def pytest_configure(config):
    config.addinivalue_line(
        "markers", "asyncio: mark test as an async test"
    )

