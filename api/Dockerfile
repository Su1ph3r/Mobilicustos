FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libmagic1 \
    libpq-dev \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Docker CLI for container orchestration
RUN curl -fsSL https://get.docker.com | sh

# Install Android SDK platform-tools (ADB) for device management
RUN curl -fsSL https://dl.google.com/android/repository/platform-tools-latest-linux.zip -o /tmp/platform-tools.zip \
    && unzip -q /tmp/platform-tools.zip -d /opt/ \
    && rm /tmp/platform-tools.zip
ENV PATH="/opt/platform-tools:${PATH}"

# Copy and install Python dependencies
COPY api/requirements.txt .
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

# Copy API code
COPY api/ /app/api/

# Create directories
RUN mkdir -p /app/uploads /app/reports /app/frida-scripts

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
