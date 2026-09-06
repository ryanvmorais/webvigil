# WebVigil engine + CLI (and, with EXTRAS="--extra web", the Web API).
#   docker build -t webvigil .
#   docker run --rm webvigil scan https://example.com
#   docker run --rm -v "$PWD:/work" webvigil report /work/scan.json --format html
# The Web API image is built by docker-compose (EXTRAS + a webvigil-web entrypoint).
FROM python:3.12-slim AS build

ARG EXTRAS=""
COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /bin/uv
ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app
# Only what the wheel build and the lockfile need — see .dockerignore.
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable ${EXTRAS}

FROM python:3.12-slim
LABEL org.opencontainers.image.source="https://github.com/ryanvmorais/webvigil" \
      org.opencontainers.image.description="A web application vulnerability scanner for developers." \
      org.opencontainers.image.licenses="Apache-2.0"

# Run as an unprivileged user; /work holds reports, /data the Web API's SQLite volume.
RUN useradd --create-home --uid 10001 webvigil \
    && mkdir /work /data \
    && chown webvigil:webvigil /work /data
COPY --from=build --chown=webvigil:webvigil /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:${PATH}"

USER webvigil
WORKDIR /work
ENTRYPOINT ["webvigil"]
CMD ["--help"]
