FROM python:3.11.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

WORKDIR /app

COPY constraints.txt /tmp/constraints.txt
COPY edge-device/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -c /tmp/constraints.txt -r /tmp/requirements.txt \
    && groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app \
    && mkdir -p /state/research-device \
    && chown app:app /state/research-device

COPY --chown=app:app shared ./shared
COPY --chown=app:app edge-device/app ./app

USER 10001:10001
CMD ["python", "-m", "app.main"]
