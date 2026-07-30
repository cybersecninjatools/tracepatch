FROM python:3.9-slim
RUN apt-get update && apt-get install -y --no-install-recommends poppler-utils && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/sectrack

COPY app/requirements.txt ./app/requirements.txt
RUN pip install --no-cache-dir -r app/requirements.txt

COPY app/ ./app/
COPY templates/ ./templates/
COPY demo/ ./demo/

RUN mkdir -p /opt/sectrack/data /opt/sectrack/uploads /opt/sectrack/tmp
ARG GIT_COMMIT=unknown
ARG BUILD_DATE=unknown
RUN echo "${GIT_COMMIT} ${BUILD_DATE}" > /opt/sectrack/VERSION

ENV SECTRACK_DB=/opt/sectrack/data/sectrack.db
ENV SECTRACK_UPLOADS=/opt/sectrack/uploads
ENV TMPDIR=/opt/sectrack/tmp
ENV SECTRACK_ORG_NAME="Your Organization"

EXPOSE 5000

CMD ["gunicorn", "--workers", "2", "--bind", "0.0.0.0:5000", "--timeout", "120", "--access-logfile", "-", "--error-logfile", "-", "app.app:app"]
