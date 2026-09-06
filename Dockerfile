# WebVigil engine + CLI (no `web` extra).
#   docker build -t webvigil .
#   docker run --rm webvigil scan https://example.com
#   docker run --rm -v "$PWD:/work" webvigil report /work/scan.json --format html
FROM python:3.12-slim AS build

COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /bin/uv
ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app
# Only what the wheel build and the lockfile need — see .dockerignore.
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.12-slim
LABEL org.opencontainers.image.source="https://github.com/ryanvmorais/webvigil" \
      org.opencontainers.image.description="A web application vulnerability scanner for developers." \
      org.opencontainers.image.licenses="Apache-2.0"

# Run as an unprivileged user; /work is a convenient mount point for reports.
RUN useradd --create-home --uid 10001 webvigil && mkdir /work && chown webvigil:webvigil /work
COPY --from=build --chown=webvigil:webvigil /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:${PATH}"

USER webvigil
WORKDIR /work
ENTRYPOINT ["webvigil"]
CMD ["--help"]
