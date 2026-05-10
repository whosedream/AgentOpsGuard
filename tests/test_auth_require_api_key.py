from fastapi import HTTPException
from starlette.datastructures import State

from agentops_guard.backend.auth import require_api_key


def test_require_api_key_rejects_invalid_token_with_request_stub():
    request = type("RequestStub", (), {"state": State()})()
    try:
        require_api_key(request=request, x_agentops_api_key="bad-key")
    except HTTPException as exc:
        assert exc.status_code == 401
    else:
        raise AssertionError("invalid key should be rejected")
