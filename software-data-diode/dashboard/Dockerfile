FROM python:3.11.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV HOME=/tmp

WORKDIR /app

COPY constraints.txt /tmp/constraints.txt
COPY dashboard/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -c /tmp/constraints.txt -r /tmp/requirements.txt \
    && groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app

COPY --chown=app:app dashboard/app.py ./app.py
COPY --chown=app:app dashboard/.streamlit ./.streamlit

USER 10001:10001
EXPOSE 8501
CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501", "--server.headless=true", "--browser.gatherUsageStats=false"]
