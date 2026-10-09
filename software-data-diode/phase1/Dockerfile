FROM python:3.11.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app
WORKDIR /app
COPY constraints.txt /tmp/constraints.txt
COPY phase1/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -c /tmp/constraints.txt -r /tmp/requirements.txt \
    && groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app \
    && mkdir /logs && chown app:app /logs
COPY --chown=app:app phase1 ./phase1
USER 10001:10001
CMD ["uvicorn", "phase1.app:app_from_env", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers"]
