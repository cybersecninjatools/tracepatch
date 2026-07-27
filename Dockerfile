FROM python:3.9-slim

WORKDIR /opt/sectrack

COPY app/requirements.txt ./app/requirements.txt
RUN pip install --no-cache-dir -r app/requirements.txt

COPY app/ ./app/
COPY templates/ ./templates/

RUN mkdir -p /opt/sectrack/data /opt/sectrack/uploads /opt/sectrack/tmp

ENV SECTRACK_DB=/opt/sectrack/data/sectrack.db
ENV SECTRACK_UPLOADS=/opt/sectrack/uploads
ENV TMPDIR=/opt/sectrack/tmp
ENV SECTRACK_ORG_NAME="Your Organization"

EXPOSE 5000

CMD ["gunicorn", "--workers", "2", "--bind", "0.0.0.0:5000", "--timeout", "120", "--access-logfile", "-", "--error-logfile", "-", "app.app:app"]
