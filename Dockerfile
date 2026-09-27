FROM python:3.11-slim-bookworm

COPY --from=ghcr.io/astral-sh/uv:0.12.15 /uv /uvx /bin/

WORKDIR /app
RUN useradd --create-home --uid 10001 appuser

COPY pyproject.toml uv.lock README.md ./
COPY src ./src
COPY data ./data
COPY schemas ./schemas

RUN uv sync --frozen --no-dev \
    && mkdir -p /app/results \
    && chown -R appuser:appuser /app

USER appuser
EXPOSE 8765
ENV PYTHONUNBUFFERED=1
CMD ["uv", "run", "cwe-vuln-ui", "--host", "127.0.0.1", "--port", "8765"]
