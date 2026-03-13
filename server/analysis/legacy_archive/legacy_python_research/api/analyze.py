from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, Literal, Optional, List

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ..analyzers.domain import analyze_domain_explain, analyze_domain_explain_async
from ..analyzers.ip import analyze_ip_explain, analyze_ip_explain_async
from ..analyzers.url import analyze_url_explain, analyze_url_explain_async
from ..persistence.sqlite_store import save_analysis
from ..utils.logging_utils import log_analysis_event
from ..utils.validators import detect_target_type
from ..utils.reputation import reputation_service
from ..utils.observability import (
    get_metrics, record_batch_analysis, record_error, record_scan, record_signal_fired
)


logger = logging.getLogger("security_analyzer")
router = APIRouter(tags=["analyze"])


@router.get("/reputation/status")
def reputation_status():
    return reputation_service.get_status()


class AnalyzeRequest(BaseModel):
    # Preferred input
    target: Optional[str] = Field(None, description="Domain, URL, or IP address")

    # Backwards/FE-compatible input
    input: Optional[str] = Field(None, description="Domain, URL, or IP address")
    type: Optional[Literal["domain", "url", "ip"]] = Field(None, description="Optional explicit type")

    verbose: bool = Field(False, description="Reserved for future debug output")


class BatchAnalyzeRequest(BaseModel):
    """Batch analysis request."""
    inputs: List[str] = Field(..., description="List of domains/URLs/IPs to analyze")
    max_concurrent: int = Field(5, description="Maximum concurrent analyses (default 5)")


def _resolve_target(req: AnalyzeRequest) -> str:
    t = (req.target or req.input or "").strip()
    if not t:
        raise ValueError("Missing target")
    return t


@router.post("/analyze", status_code=201)
async def analyze(req: AnalyzeRequest) -> Dict[str, Any]:
    start = time.perf_counter()

    try:
        target = _resolve_target(req)

        # Compute analysis (public result) and explain blob (for persistence).
        if req.type == "url":
            result, explain = await analyze_url_explain_async(target)
        elif req.type == "ip":
            result, explain = await analyze_ip_explain_async(target)
        elif req.type == "domain":
            result, explain = await analyze_domain_explain_async(target)
        else:
            detected, normalized = detect_target_type(target)
            if detected == "url":
                result, explain = await analyze_url_explain_async(target)
            elif detected == "ip":
                result, explain = await analyze_ip_explain_async(normalized)
            else:
                result, explain = await analyze_domain_explain_async(normalized)

        analysis_id = None
        persistence_ok = False
        try:
            analysis_id = save_analysis(result=result, explain=explain)
            persistence_ok = True
        except Exception as e:
            # Best-effort persistence: log the error but don't fail the primary request.
            logger.error(f"Persistence failed for {target}: {e}")
            persistence_ok = False

        latency_ms = int((time.perf_counter() - start) * 1000)
        
        # Record metrics
        record_scan(latency_ms)
        for signal in result.get("signals", []):
            record_signal_fired(signal.get("name", "unknown"))
        
        log_analysis_event(
            logger,
            analysis_id=analysis_id,
            target=str(result.get("target", target)),
            target_type=str(result.get("type", "")),
            verdict=str(result.get("verdict", "")),
            risk_score=int(result.get("risk_score", 0)),
            confidence=float(result.get("confidence", 0.0)),
            latency_ms=latency_ms,
            persistence_ok=persistence_ok,
        )

        return result

    except ValueError as e:
        record_error()
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        record_error()
        raise HTTPException(status_code=500, detail=f"Analysis failed: {e}")


async def _analyze_single(target: str) -> Dict[str, Any]:
    """Analyze a single target (helper for batch analysis)."""
    try:
        detected, normalized = detect_target_type(target)
        
        if detected == "url":
            result, _ = await analyze_url_explain_async(target)
        elif detected == "ip":
            result, _ = await analyze_ip_explain_async(normalized)
        else:
            result, _ = await analyze_domain_explain_async(normalized)
        
        return result
    except Exception as e:
        logger.error(f"Batch analysis failed for {target}: {e}")
        return {
            "target": target,
            "input": target,
            "error": str(e),
            "risk_score": None,
            "verdict": "error",
        }


@router.post("/batch_analyze", status_code=201)
async def batch_analyze(req: BatchAnalyzeRequest) -> Dict[str, Any]:
    """Analyze multiple targets concurrently with a worker pool."""
    if not req.inputs:
        raise HTTPException(status_code=400, detail="No inputs provided")
    
    if len(req.inputs) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 inputs allowed per batch")
    
    start = time.perf_counter()
    record_batch_analysis()
    
    # Create a semaphore to limit concurrent analyses
    sem = asyncio.Semaphore(req.max_concurrent)
    
    async def bounded_analyze(target: str) -> Dict[str, Any]:
        async with sem:
            return await _analyze_single(target)
    
    # Run all analyses concurrently with concurrency limit
    tasks = [bounded_analyze(target) for target in req.inputs]
    results = await asyncio.gather(*tasks, return_exceptions=False)
    
    latency_ms = int((time.perf_counter() - start) * 1000)
    
    # Filter for malicious/suspicious
    malicious_count = sum(1 for r in results if r.get("verdict") in ["malicious", "suspicious"])
    
    return {
        "batch_id": None,  # Can be populated if persistent storage is added
        "total_inputs": len(req.inputs),
        "completed": len(results),
        "malicious_count": malicious_count,
        "latency_ms": latency_ms,
        "results": results,
    }


@router.get("/metrics")
def metrics() -> Dict[str, Any]:
    """Get operational metrics."""
    return get_metrics()

