# WebVigil engine + CLI (and, with EXTRAS="--extra web", the Web API).
#   docker build -t webvigil .
#   docker run --rm webvigil scan https://example.com
#   docker run --rm -v "$PWD:/work" webvigil report /work/scan.json --format html
# The Web API image is built by docker-compose (EXTRAS + a webvigil-web entrypoint).
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS build

ARG EXTRAS=""
COPY --from=ghcr.io/astral-sh/uv:0.11@sha256:77280f2f771df71f90786c314fe1bbc1e023feac652969bbf139c280babf2eb7 /uv /bin/uv
ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app
# Only what the wheel build and the lockfile need — see .dockerignore.
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
# --locked: the build fails if uv.lock no longer matches pyproject.toml, so the image never
# installs a graph the CI did not test.
RUN uv sync --locked --no-dev --no-editable ${EXTRAS}

FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928
LABEL org.opencontainers.image.source="https://github.com/ryanvmorais/webvigil" \
      org.opencontainers.image.description="A web application vulnerability scanner for developers." \
      org.opencontainers.image.licenses="Apache-2.0"

# Debian's security updates that the base image does not carry yet: Debian publishes a fix before
# the official Python image is rebuilt, and the release refuses an image with a fixable HIGH or
# CRITICAL vulnerability. A rebuild picks up whatever Debian has fixed since.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*
# Run as an unprivileged user; /work holds reports, /data the Web API's SQLite volume.
RUN useradd --create-home --uid 10001 webvigil \
    && mkdir /work /data \
    && chown webvigil:webvigil /work /data
# The runtime never calls pip (the venv comes from the build stage), and the base image's pip vendors
# its own certifi, which scanners flag until the base image is rebuilt. Dropping it removes both.
RUN python -m pip uninstall -y pip
COPY --from=build --chown=webvigil:webvigil /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:${PATH}"

USER webvigil
WORKDIR /work
ENTRYPOINT ["webvigil"]
CMD ["--help"]
