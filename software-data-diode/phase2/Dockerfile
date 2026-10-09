FROM python:3.11.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app
WORKDIR /app
COPY constraints.txt /tmp/constraints.txt
COPY phase1/requirements.txt /tmp/phase1/requirements.txt
COPY phase2/requirements.txt /tmp/phase2/requirements.txt
RUN pip install --no-cache-dir -c /tmp/constraints.txt -r /tmp/phase2/requirements.txt \
    && groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app \
    && mkdir /state /private /public && chown app:app /state /private /public
COPY --chown=app:app phase1 ./phase1
COPY --chown=app:app shared ./shared
COPY --chown=app:app phase2 ./phase2
USER 10001:10001
CMD ["uvicorn", "phase2.app:app_from_env", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers"]
