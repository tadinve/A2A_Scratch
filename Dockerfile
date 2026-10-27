# One image for every A2A service (Day 08). SERVICE_APP picks the ASGI app at runtime:
#   docker run -e SERVICE_APP=identity_service.app:app -e PORT=8080 ...
#
# Dependencies come only from uv.lock (--frozen). No .env, key, database or test file is
# copied (see .dockerignore): secrets reach the container from Secret Manager at runtime.
FROM python:3.13-slim

# uv from PyPI, where every dependency comes from anyway: one registry fewer to reach
# (a build once failed on a timeout fetching ghcr.io/astral-sh/uv).
RUN pip install --no-cache-dir --disable-pip-version-check uv==0.13.1

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    PYTHONUNBUFFERED=1 \
    PORT=8080

WORKDIR /app

# Dependencies first, in their own layer, so code changes don't reinstall them.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY . .

RUN useradd --system --uid 10001 --no-create-home app
USER app
ENV PATH=/app/.venv/bin:$PATH

# One worker: each instance is one process (Cloud Run scales instances, not workers).
# --proxy-headers: Cloud Run terminates TLS in front of the container.
CMD ["sh", "-c", "exec uvicorn \"${SERVICE_APP:?set SERVICE_APP, e.g. identity_service.app:app}\" --host 0.0.0.0 --port \"${PORT}\" --workers 1 --proxy-headers --forwarded-allow-ips='*'"]
