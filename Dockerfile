# PhishGuard FastAPI app - production container

# ---------- builder ----------
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Build deps required for scikit-learn, lxml, scapy, oletools, etc.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        libxml2-dev \
        libxslt1-dev \
        libffi-dev \
        libssl-dev \
        libpcap-dev \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY requirements.txt requirements-threatlens.txt ./

RUN pip install --upgrade pip && \
    pip install --prefix=/install -r requirements.txt && \
    pip install --prefix=/install \
        "crawl4ai>=0.4.0" \
        "scrapling>=0.2.0" \
        "trafilatura>=1.12.0" \
        "lxml_html_clean>=0.4.0" || true


# ---------- runtime ----------
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000

# Runtime libs only (no build toolchain)
RUN apt-get update && apt-get install -y --no-install-recommends \
        libxml2 \
        libxslt1.1 \
        libpcap0.8 \
        libffi8 \
        tesseract-ocr \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1001 --shell /bin/bash phishguard \
    && groupadd -g 999 docker 2>/dev/null || true \
    && usermod -aG docker phishguard

COPY --from=builder /install /usr/local

WORKDIR /app
COPY --chown=phishguard:phishguard app /app/app
COPY --chown=phishguard:phishguard requirements.txt /app/requirements.txt

# Writable data dirs (audit log, ML model, training set)
RUN mkdir -p /app/data /app/data/training /app/data/cache /app/credentials \
    && chown -R phishguard:phishguard /app/data /app/credentials

USER phishguard

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fs http://localhost:8000/health || exit 1

# Single worker: the app holds in-process singletons (SMTP gateway on :8025, the
# bombing detector + rate-limiter state, and the daemon schedulers). With >1 worker
# only one binds SMTP, detector/rate-limiter state splits per-process (so /api/bombing
# stats read wrong on the other worker), and schedulers double-run. FastAPI is async,
# so one worker still serves many concurrent dashboard requests.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
