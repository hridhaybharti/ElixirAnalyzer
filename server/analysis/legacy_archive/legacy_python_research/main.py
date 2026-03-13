from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from backend.api.analyze import router as analyze_router
from backend.api.explain import router as explain_router
from backend.api.history import router as history_router
from backend.persistence.sqlite_store import init_db
from backend.utils.reputation import reputation_service
from backend.utils.api_security import (
    get_rate_limiter, get_api_key_manager, generate_request_id, store_request_metadata
)


def create_app() -> FastAPI:
    app = FastAPI(
        title="Security Analyzer API",
        description=(
            "Heuristic-based analysis for domains, URLs, and IP addresses. "
            "Outputs explainable signals, a 0-100 risk score, confidence, and a verdict."
        ),
        version="1.1.0",
    )

    # CORS middleware (adjust origins as needed)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Change to specific origins in production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def add_request_metadata(request: Request, call_next):
        """Add request ID and track security metrics."""
        request_id = generate_request_id()
        
        # Get client IP
        client_ip = request.client.host if request.client else "unknown"
        
        # Check rate limit
        rate_limiter = get_rate_limiter(requests_per_minute=60)
        if not rate_limiter.is_allowed(client_ip):
            reset_time = rate_limiter.get_reset_time(client_ip)
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded. Retry after {reset_time:.0f}s",
                headers={"Retry-After": f"{int(reset_time) + 1}"},
            )
        
        # Check API key if provided
        api_key_header = request.headers.get("X-API-Key")
        if api_key_header:
            api_key_manager = get_api_key_manager()
            if not api_key_manager.validate_key(api_key_header):
                raise HTTPException(status_code=403, detail="Invalid API key")
            api_key_manager.record_use(api_key_header)
        
        # Store metadata
        store_request_metadata(request_id, {
            "method": request.method,
            "path": request.url.path,
            "client_ip": client_ip,
            "api_key": bool(api_key_header),
        })
        
        # Add request ID to response headers
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

    @app.on_event("startup")
    def _startup() -> None:
        init_db()
        reputation_service.load_dataset()

    app.include_router(analyze_router, prefix="/api")
    app.include_router(history_router, prefix="/api")
    app.include_router(explain_router, prefix="/api")

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/api/security/keys")
    def list_api_keys():
        """List all API keys (admin endpoint, consider protecting)."""
        return get_api_key_manager().list_keys()

    @app.post("/api/security/generate-key")
    def generate_api_key(name: str = "default"):
        """Generate a new API key (admin endpoint, consider protecting)."""
        return {"key": get_api_key_manager().generate_key(name)}

    return app


app = create_app()
