FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libmagic1 \
    libpq-dev \
    curl \
    unzip \
    xz-utils \
    default-jdk-headless \
    && rm -rf /var/lib/apt/lists/*

# Install apktool for APK decompilation/repackaging
RUN curl -fsSL -o /usr/local/bin/apktool.jar \
    "https://bitbucket.org/iBotPeaches/Apktool/downloads/apktool_2.9.3.jar" \
    && printf '#!/bin/bash\njava -jar /usr/local/bin/apktool.jar "$@"\n' > /usr/local/bin/apktool \
    && chmod +x /usr/local/bin/apktool

# Install Android build-tools (zipalign, apksigner) via cmdline-tools
RUN mkdir -p /opt/android-sdk/cmdline-tools \
    && curl -fsSL "https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip" -o /tmp/cmdline-tools.zip \
    && unzip -q /tmp/cmdline-tools.zip -d /opt/android-sdk/cmdline-tools/ \
    && mv /opt/android-sdk/cmdline-tools/cmdline-tools /opt/android-sdk/cmdline-tools/latest \
    && rm /tmp/cmdline-tools.zip \
    && yes | /opt/android-sdk/cmdline-tools/latest/bin/sdkmanager --sdk_root=/opt/android-sdk "build-tools;34.0.0"
ENV PATH="/opt/android-sdk/build-tools/34.0.0:${PATH}"

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

# Download drozer agent APK for on-device installation
RUN mkdir -p /app/tools && \
    curl -fSL -o /app/tools/drozer-agent.apk \
    "https://github.com/WithSecureLabs/drozer-agent/releases/latest/download/drozer-agent.apk" || \
    echo "Drozer agent APK download failed (non-fatal, can be installed later)"

# Copy API code
COPY api/ /app/api/

# Create directories
RUN mkdir -p /app/uploads /app/reports /app/frida-scripts

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
