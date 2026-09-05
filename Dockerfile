FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim@sha256:e5b65587bce7de595f299855d7385fe7fca39b8a74baa261ba1b7147afa78e58
WORKDIR /app
ENV UV_LINK_MODE=copy
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv UV_HTTP_TIMEOUT=300 uv sync --locked --no-dev --extra semantic --no-install-project
COPY README.md alembic.ini ./
COPY src ./src
COPY policies ./policies
COPY alembic ./alembic
RUN --mount=type=cache,target=/root/.cache/uv uv sync --locked --no-dev --extra semantic --offline
RUN useradd --create-home --uid 10001 agentops && chown -R agentops:agentops /app
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1
USER 10001:10001
EXPOSE 8000
