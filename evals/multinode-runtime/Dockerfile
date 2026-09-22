# Offline test image: the reviewed lock and cached dependencies, never a host venv.
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim@sha256:e5b65587bce7de595f299855d7385fe7fca39b8a74baa261ba1b7147afa78e58
COPY --from=uv_runtime uv /usr/local/bin/uv
RUN echo "92face6b1f0462ad911857957bd168cd4ae45515e2a2cb3fcc3ecbda3d4d82b1  /usr/local/bin/uv" | sha256sum -c -
RUN uv --version
WORKDIR /app
ENV UV_LINK_MODE=copy PYTHONDONTWRITEBYTECODE=1
COPY pyproject.toml uv.lock ./
RUN --mount=type=bind,from=uv_cache,target=/uv-cache,rw UV_CACHE_DIR=/uv-cache uv sync --offline --locked --no-dev --extra semantic --no-install-project
COPY README.md alembic.ini ./
COPY src ./src
COPY policies ./policies
COPY alembic ./alembic
RUN --mount=type=bind,from=uv_cache,target=/uv-cache,rw UV_CACHE_DIR=/uv-cache uv sync --offline --locked --no-dev --extra semantic
COPY --from=probe_runtime runtime.py /app/eval_runtime.py
COPY --from=receipt_fixture receipt_mcp_server.py /app/receipt_mcp_server.py
RUN useradd --create-home --uid 10001 agentops && chown agentops:agentops /app
ENV PATH="/app/.venv/bin:$PATH"
USER 10001:10001
RUN python -c "import torch, mcp, sqlalchemy, uvicorn"
