FROM python:3.11-slim

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

# Copy application code
COPY backend/ ./backend/
COPY dashboard/ ./dashboard/
COPY mobile/ ./mobile/

# Non-root user for security
RUN useradd -r -s /bin/false veritas
RUN mkdir -p /data && chown veritas:veritas /data
USER veritas

# Database stored in persistent volume
ENV VERITAS_DB_PATH=/data/veritas.db

EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
