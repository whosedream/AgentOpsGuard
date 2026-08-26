FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim
WORKDIR /app
COPY pyproject.toml uv.lock README.md alembic.ini ./
COPY src ./src
COPY policies ./policies
COPY alembic ./alembic
RUN --mount=type=cache,target=/root/.cache/uv UV_HTTP_TIMEOUT=300 uv sync --no-dev --extra semantic
ENV PATH="/app/.venv/bin:$PATH"
EXPOSE 8000
