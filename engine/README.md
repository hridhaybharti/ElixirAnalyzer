# engine (Python compatibility)

Legacy compatibility shims for older imports. New development should use `backend/` directly.

- `analyzer.py`: re-exports `backend.analyzers.url` and provides a legacy API shape.
- `signals.py`: maps legacy signal functions to `backend.heuristics`.
- `verdict.py`: delegates to `backend.core.verdict` and adds helper functions.
