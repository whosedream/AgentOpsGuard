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


@app.exception_handler(RequestValidationError)
async def validation_error(_request: Request, _error: RequestValidationError) -> JSONResponse:
    return JSONResponse(status_code=422, content={"detail": "Invalid request"})


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/readyz")
def readyz() -> dict[str, str]:
    scanner = _local_scanner()
    try:
        scanner.warm()
    except SemanticScannerUnavailable as exc:
        raise HTTPException(503, "Semantic model unavailable") from exc
    return {"status": "ok"}


@app.post("/v1/score", response_model=ScoreResponse)
def score(payload: ScoreRequest) -> ScoreResponse:
    scanner = _local_scanner()
    try:
        assessment = scanner.assess(ScanRequest(content=payload.text, source="external"))
    except SemanticScannerUnavailable as exc:
        raise HTTPException(503, "Semantic model unavailable") from exc
    if assessment is None or assessment.score is None:
        raise HTTPException(503, "Semantic model unavailable")
    return ScoreResponse(score=assessment.score, model=assessment.model)


def _local_scanner() -> SemanticScanner:
    scanner = get_semantic_scanner()
    if not isinstance(scanner, SemanticScanner):
        raise HTTPException(503, "Semantic model unavailable")
    return scanner
