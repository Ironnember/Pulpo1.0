FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd --system pulpo && useradd --system --gid pulpo --home-dir /nonexistent --shell /usr/sbin/nologin pulpo

WORKDIR /opt/pulpo

COPY pyproject.toml ./pyproject.toml
COPY pulpo ./pulpo
COPY custody-service ./custody-service

RUN python -m pip install --no-cache-dir '.[authority]' './custody-service' \
    && mkdir -p /var/lib/pulpo \
    && chown -R pulpo:pulpo /var/lib/pulpo /opt/pulpo

USER pulpo

EXPOSE 8080
VOLUME ["/var/lib/pulpo"]

HEALTHCHECK --interval=5s --timeout=2s --start-period=5s --retries=6 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=1).read()" || exit 1

CMD ["uvicorn", "pulpo_custody_service.main:app", "--app-dir", "custody-service/src", "--host", "0.0.0.0", "--port", "8080", "--workers", "1", "--no-access-log"]
