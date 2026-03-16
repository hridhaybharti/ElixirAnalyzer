Shim Mappings for Tests

- tests/test_api_security.py -> backend/utils/api_security.py
- tests/test_domain_heuristics.py & tests/test_typosquatting.py -> backend/heuristics/domain_heuristics.py
- tests/test_url_heuristics.py -> backend/heuristics/url_heuristics.py
- tests/test_observability.py -> backend/utils/observability.py
- tests/test_persistence.py -> backend/persistence/sqlite_store.py
- tests/test_graph_analysis.py -> backend/engine/graph_analysis.py
- tests/test_scorer.py -> backend/core/scorer.py & backend/core/weights.py
- tests/test_validators.py -> backend/utils/validators.py
- tests/test_reputation_cache.py -> backend/utils/reputation_cache.py
- tests/test_threat_intel.py -> backend/utils/threat_intel.py
