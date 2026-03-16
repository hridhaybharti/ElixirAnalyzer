# Test Harness

This repository includes lightweight shims to enable the Python test suite to run in a focused manner.

How to run locally:
- Quick all-tests run:
```bash
python3 scripts/run_all_tests.py
```
- Individual tests:
```bash
pytest tests/test_domain_heuristics.py -q
```

Shim mapping overview (see docs/SHIMS_MAP.md for details):
- backend/utils/api_security.py maps to tests/test_api_security.py
- backend/heuristics/domain_heuristics.py maps to tests/test_domain_heuristics.py and tests/test_typosquatting.py
- backend/heuristics/url_heuristics.py maps to tests/test_url_heuristics.py
- backend/utils/observability.py maps to tests/test_observability.py
- backend/persistence/sqlite_store.py maps to tests/test_persistence.py
- backend/engine/graph_analysis.py maps to tests/test_graph_analysis.py and GraphAnalyzer usage
- backend/core/scorer.py and backend/core/weights.py map to tests/test_scorer.py
- backend/utils/validators.py maps to tests/test_validators.py
- backend/utils/reputation_cache.py maps to tests/test_reputation_cache.py
- backend/utils/threat_intel.py maps to tests/test_threat_intel.py
