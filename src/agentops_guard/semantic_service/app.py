import anyio
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from agentops_guard.backend.schemas import ScanRequest
from agentops_guard.backend.services.semantic_scanner import (
    MAX_MODEL_CHARACTERS,
    SemanticScanner,
    SemanticScannerUnavailable,
    get_semantic_scanner,
)


class ScoreRequest(BaseModel):
    text: str = Field(max_length=MAX_MODEL_CHARACTERS)


class ScoreResponse(BaseModel):
    score: float
    model: str


app = FastAPI(title="AgentOps Guard Semantic Scorer")
# Readiness can initialize/verify model assets, so keep that work off the event
# loop without making probes queue behind the scoring thread pool. This limit
# does not add inference capacity or cache a previous readiness result.
_readiness_limiter = anyio.CapacityLimiter(1)


@app.exception_handler(RequestValidationError)
async def validation_error(_request: Request, _error: RequestValidationError) -> JSONResponse:
    return JSONResponse(status_code=422, content={"detail": "Invalid request"})


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/readyz")
async def readyz() -> dict[str, str]:
    await anyio.to_thread.run_sync(_check_ready, limiter=_readiness_limiter)
    return {"status": "ok"}


def _check_ready() -> None:
    try:
        scanner = _local_scanner()
        scanner.warm()
    except SemanticScannerUnavailable as exc:
        raise HTTPException(503, {"code": exc.reason}) from exc


@app.post("/v1/score", response_model=ScoreResponse)
def score(payload: ScoreRequest) -> ScoreResponse:
    scanner = _local_scanner()
    try:
        assessment = scanner.assess(ScanRequest(content=payload.text, source="external"))
    except SemanticScannerUnavailable as exc:
        raise HTTPException(503, {"code": exc.reason}) from exc
    if assessment is None or assessment.score is None:
        raise HTTPException(503, "Semantic model unavailable")
    return ScoreResponse(score=assessment.score, model=assessment.model)


def _local_scanner() -> SemanticScanner:
    scanner = get_semantic_scanner()
    if not isinstance(scanner, SemanticScanner):
        raise HTTPException(503, "Semantic model unavailable")
    return scanner
