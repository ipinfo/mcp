FROM python:3.14-slim@sha256:caaf356f40667c496d405780745b9ac25771c189a51dfcc42430d531ea09f8a2

COPY --from=ghcr.io/astral-sh/uv:0.12.18@sha256:3adc3706091ce7c2fe595e669628caedd6d951551b92b258b7e7dbe06d9440bc /uv /uvx /bin/

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
