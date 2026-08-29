FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd --system pulpo && useradd --system --gid pulpo --home-dir /nonexistent --shell /usr/sbin/nologin pulpo

WORKDIR /opt/pulpo

COPY pyproject.toml ./pyproject.toml
COPY pulpo ./pulpo
COPY authority-service ./authority-service

RUN python -m pip install --no-cache-dir '.[authority]' './authority-service' \
    && mkdir -p /var/lib/pulpo/authority /run/pulpo-authority \
    && chown -R pulpo:pulpo /var/lib/pulpo/authority /opt/pulpo

USER pulpo

EXPOSE 8443
VOLUME ["/var/lib/pulpo/authority"]

HEALTHCHECK --interval=5s --timeout=2s --start-period=5s --retries=6 \
  CMD python -c "import os,ssl,urllib.request; c=ssl._create_unverified_context(); urllib.request.urlopen('https://127.0.0.1:'+os.environ['PULPO_AUTHORITY_PORT']+'/health', context=c, timeout=1).read()" || exit 1

CMD ["python", "-m", "pulpo_authority_service.local_runtime"]
