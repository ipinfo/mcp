FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928

COPY --from=ghcr.io/astral-sh/uv:0.13.4@sha256:9f130421e930bfbdc563c00740466603f8723158e90297d07957c2294640262b /uv /uvx /bin/

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
