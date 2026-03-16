FROM python:3.14-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

COPY pyproject.toml uv.lock README.md LICENSE.txt ./
RUN uv sync --no-dev --locked --no-install-project

COPY src/ src/
RUN uv sync --no-dev --locked

ENV IPINFO_TRANSPORT=http
ENV HOST=0.0.0.0
ENV PORT=8000

EXPOSE 8000

CMD ["uv", "run", "ipinfo-mcp-server"]
