FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency requirements
COPY requirements.txt pyproject.toml /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY app/ /app/app/
COPY lab/ /app/lab/
COPY scripts/ /app/scripts/

# Create runtime directories
RUN mkdir -p /app/storage/reports /app/storage/evidence

# Expose Web Interface Port
EXPOSE 8000

# Run Uvicorn Server
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
