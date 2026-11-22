# syntax=docker/dockerfile:1
# OmniJarvis light Python worker — Hugging Face Spaces (Docker SDK).
# Replaces the Render free Web Service (render.yaml), which is
# CARD-BLOCKED. Same code as render/worker/main.py (byte-identical copy
# in this directory), same system deps as render.yaml's buildCommand.
#
# HF Spaces notes (verified against HF docs 2026-11-22):
# - The container runs as UID 1000, not root -> create appuser (1000)
#   and run as that user; /app is owned by appuser, HOME is writable
#   (fontconfig/WeasyPrint cache).
# - HF sets $PORT (default 7860); uvicorn binds ${PORT:-7860}.
#   app_port: 7860 in README.md frontmatter must match.
# - Space must be PUBLIC: the worker has no auth by design (same
#   posture as the Render plan). The auth boundary is the hub's docs
#   routes (signed device / x-internal-secret), not this worker.
# - No `hardware` key exists in Space frontmatter; cpu-basic is
#   requested via the Hub API in deploy.py (it is the default).
# - Expected image size ~300-350 MB: python:3.12-slim ~135 MB,
#   apt layer ~120 MB (tesseract ~35, poppler ~35, pango/cairo/
#   glib ~30, fonts ~15), pip layer ~60 MB (WeasyPrint stack ~35,
#   pdfplumber ~8, Pillow ~5, FastAPI/uvicorn ~8, segno ~1).
#   HF Spaces free CPU is 2 vCPU / 16 GB RAM, so this fits easily
#   (the Render fit problem was 512 MB, not the image size).
FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=7860

# System deps — parity with render.yaml buildCommand, plus the
# WeasyPrint runtime libs render.yaml relied on implicitly:
#   tesseract-ocr + tesseract-ocr-hin (OCR, eng+hin)
#   poppler-utils (pdftoppm — PDF page render for OCR)
#   fonts-lohit-deva (Devanagari glyphs) + fonts-dejavu-core (Latin)
#   libpango-1.0-0, libpangoft2-1.0-0, libharfbuzz0b, libffi8,
#   libcairo2, libgdk-pixbuf-2.0-0, libglib2.0-0 (WeasyPrint 61)
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    tesseract-ocr-hin \
    poppler-utils \
    fonts-lohit-deva \
    fonts-dejavu-core \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libharfbuzz0b \
    libffi8 \
    libcairo2 \
    libgdk-pixbuf-2.0-0 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# HF Spaces runs the container as UID 1000.
RUN useradd -m -u 1000 appuser

WORKDIR /app

COPY requirements.txt requirements-heavy.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Heavy deps (Track D, 2026-11-22): docling + browser-use/playwright.
# OFF by default — the light image fits 512 MB hosts (Koyeb free).
# Build with --build-arg INSTALL_HEAVY=1 only on a >=16 GB host
# (HF Spaces cpu-basic with PRO). Uses the CPU torch index (default
# PyPI pulls multi-GB CUDA wheels) and installs Chromium for
# Playwright. The worker lazy-imports these and 503s honestly when
# they are absent, so the light image is fully functional without them.
ARG INSTALL_HEAVY=0
RUN if [ "$INSTALL_HEAVY" = "1" ]; then \
      pip install --no-cache-dir --extra-index-url https://download.pytorch.org/whl/cpu -r requirements-heavy.txt \
      && python -m playwright install chromium --with-deps; \
    fi

COPY main.py .

RUN chown -R appuser:appuser /app

USER appuser
ENV HOME=/home/appuser

EXPOSE 7860

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:${PORT:-7860}/health', timeout=4)"

CMD ["sh", "-c", "exec uvicorn main:app --host 0.0.0.0 --port ${PORT:-7860}"]
