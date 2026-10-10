FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY wsgi.py entrypoint.sh ./

RUN useradd --system --create-home --uid 1000 custody \
 && mkdir -p /data/evidence && chown custody /data/evidence \
 && chmod +x entrypoint.sh
USER custody

ENV EVIDENCE_DIR=/data/evidence FLASK_APP=wsgi.py
EXPOSE 8000
ENTRYPOINT ["./entrypoint.sh"]
