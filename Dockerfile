FROM python:3.11-slim

WORKDIR /app

# Set non-buffering for standard output to capture live Cloud Run logs
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PORT=8080

# Install system build dependencies if necessary
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install pinned dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Expose HTTP port
EXPOSE 8080

# Cloud Run injects $PORT environment variable at runtime
CMD exec uvicorn aegis.app:app --host 0.0.0.0 --port ${PORT}
