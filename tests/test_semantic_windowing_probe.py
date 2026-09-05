from pathlib import Path

import pytest

from agentops_guard.backend.services.semantic_scanner import SemanticScannerUnavailable


@pytest.fixture
def windowing(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    import semantic_windowing_probe_lib

    return semantic_windowing_probe_lib


def test_full_safe_model_text_redacts_before_windowing(windowing):
    secret = "sk-abcdefghijklmnopqrstuvwxyz123456"

    safe = windowing.full_safe_model_text(f"prefix token={secret} suffix")

    assert secret not in safe
    assert "[REDACTED:" in safe


def test_chunk_indices_overlap_and_cover_tail(windowing):
    starts = windowing.chunk_start_indices(
        1_100,
        window_tokens=510,
        overlap_tokens=64,
        max_chunks=4,
    )

    assert starts == [0, 446, 892]
    assert starts[-1] + 510 >= 1_100


def test_chunk_indices_fail_instead_of_silently_skipping_content(windowing):
    with pytest.raises(SemanticScannerUnavailable, match="coverage limit"):
        windowing.chunk_start_indices(
            10_000,
            window_tokens=510,
            overlap_tokens=64,
            max_chunks=2,
        )


@pytest.mark.parametrize(
    ("window", "overlap", "chunks"),
    [(0, 0, 1), (10, 10, 1), (10, -1, 1), (10, 1, 0)],
)
def test_chunk_indices_reject_invalid_limits(
    windowing, window: int, overlap: int, chunks: int
):
    with pytest.raises(ValueError):
        windowing.chunk_start_indices(
            10,
            window_tokens=window,
            overlap_tokens=overlap,
            max_chunks=chunks,
        )
