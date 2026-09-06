# A deliberately-vulnerable target app for manual Active-Mode scans and demos (spec 006).
# NOT a WebVigil component — it is the fixture app from tests/, packaged to run on a port.
#   docker compose --profile targets up target
#   webvigil scan http://localhost:8080 --mode active --authorized-by me
FROM python:3.12-slim

RUN pip install --no-cache-dir "starlette>=0.37" "uvicorn>=0.30" "python-multipart>=0.0.9"

WORKDIR /app
COPY tests ./tests
ENV PYTHONPATH=/app

RUN useradd --create-home --uid 10002 target
USER target

EXPOSE 8080
CMD ["python", "-m", "uvicorn", "tests.fixtures.serve:app", "--host", "0.0.0.0", "--port", "8080"]
