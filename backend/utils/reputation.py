class ReputationService:
    @staticmethod
    def is_reputable(domain: str) -> bool:
        # Default to not reputable; tests can patch this.
        return False


# Expose a module-level singleton for monkeypatching in tests
reputation_service = ReputationService()
