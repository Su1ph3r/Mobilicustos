FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    cmake \
    ninja-build \
    build-essential \
    pkg-config \
    libicu-dev \
    libcapstone-dev \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Clone Blutter
WORKDIR /opt
RUN git clone --depth 1 https://github.com/worawit/blutter.git

WORKDIR /opt/blutter

# Install Python dependencies
RUN pip install --no-cache-dir pyelftools requests capstone

# Create working directories
RUN mkdir -p /input /output /opt/blutter/blutter_dartvm

# Pre-download common Dart SDK versions to avoid first-run delays
# Flutter 3.x series uses Dart 3.x - download arm64 builds (most common for mobile)
RUN for VERSION in 3.3.0 3.2.0 3.1.0 3.0.0 2.19.0 2.18.0 2.17.0; do \
        mkdir -p /opt/blutter/blutter_dartvm/${VERSION}_arm64 && \
        curl -fsSL --connect-timeout 30 \
            "https://storage.googleapis.com/dart-archive/channels/stable/release/${VERSION}/sdk/dartsdk-linux-arm64-release.zip" \
            -o /tmp/dart-${VERSION}.zip && \
        unzip -q /tmp/dart-${VERSION}.zip -d /opt/blutter/blutter_dartvm/${VERSION}_arm64 && \
        rm /tmp/dart-${VERSION}.zip && \
        echo "Downloaded Dart ${VERSION}" || \
        echo "Failed to download Dart ${VERSION} (may not exist)"; \
    done; true

# Pre-build Blutter's native components by running help
RUN python blutter.py --help 2>/dev/null || true

# Set entrypoint
ENTRYPOINT ["python", "blutter.py"]
CMD ["--help"]
