# Installation Guide

This guide covers detailed installation and configuration of Mobilicustos.

## Prerequisites

### Required
- **Docker Engine** 20.10 or later
- **Docker Compose** 2.0 or later
- **8GB RAM** minimum (16GB recommended)
- **20GB disk space** minimum (50GB recommended for analysis artifacts)

### Optional (for dynamic analysis)
- **Android device** (rooted) or Android emulator
- **iOS device** (jailbroken) or Corellium account
- **Genymotion** (desktop or cloud)
- **ADB** (Android Debug Bridge) for device connection

## Quick Installation

### Linux/macOS

```bash
# Clone the repository
git clone https://github.com/Su1ph3r/Mobilicustos.git
cd Mobilicustos

# Copy environment file and configure
cp .env.example .env

# Start all services
docker compose up -d

# Verify services are running
docker compose ps

# Access the application
open http://localhost:3000
```

### Windows

```powershell
# Clone the repository
git clone https://github.com/Su1ph3r/Mobilicustos.git
cd Mobilicustos

# Copy environment file
copy .env.example .env

# If using Docker Desktop, you may need to configure the socket path
# Edit .env and set: DOCKER_SOCKET_PATH=//var/run/docker.sock

# Start all services
docker compose up -d

# Access the application
start http://localhost:3000
```

## Configuration

### Environment Variables

Edit `.env` to customize your installation:

```bash
# Database Configuration
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_DB=mobilicustos
POSTGRES_USER=mobilicustos
POSTGRES_PASSWORD=changeme  # Change in production!

# Neo4j Configuration
NEO4J_URI=bolt://neo4j:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=changeme  # Change in production!

# Redis Configuration
REDIS_URL=redis://redis:6379

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
API_DEBUG=false
SECRET_KEY=generate-a-random-key-here  # Change in production!

# Analysis Paths
UPLOADS_PATH=/app/uploads
REPORTS_PATH=/app/reports

# Analysis Limits
MAX_APK_SIZE_MB=500
MAX_IPA_SIZE_MB=1000
ANALYSIS_TIMEOUT_SECONDS=3600

# Corellium (optional)
CORELLIUM_API_KEY=
CORELLIUM_DOMAIN=https://app.corellium.com
```

### Security Configuration

For production deployments:

1. **Change all default passwords** in `.env`
2. **Generate a secure SECRET_KEY**:
   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```
3. **Configure HTTPS** using a reverse proxy (nginx, traefik)
4. **Restrict network access** to management ports (5432, 7474, 7687, 6379)

## Service Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Docker Network                          │
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │ Frontend │  │   API    │  │ Report   │  │ Analyzers │   │
│  │  :3000   │  │  :8000   │  │Processor │  │ (on-demand)│   │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └──────────┘   │
│       │             │             │                         │
│       └─────────────┼─────────────┘                         │
│                     │                                        │
│  ┌──────────┐  ┌────┴─────┐  ┌──────────┐                  │
│  │PostgreSQL│  │  Neo4j   │  │  Redis   │                  │
│  │  :5432   │  │:7474/7687│  │  :6379   │                  │
│  └──────────┘  └──────────┘  └──────────┘                  │
└─────────────────────────────────────────────────────────────┘
```

## Verifying Installation

### Check Service Health

```bash
# All services should show "healthy" or "running"
docker compose ps

# Check API health
curl http://localhost:8000/api/health

# Check frontend
curl -I http://localhost:3000
```

### View Logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f api
docker compose logs -f frontend
```

## Device Setup

### Android Device/Emulator

1. **Enable USB debugging** on the device
2. **Connect via ADB**:
   ```bash
   adb devices
   ```
3. **For rooted devices**, ensure `su` binary is available
4. **Discover devices** via API:
   ```bash
   curl -X POST http://localhost:8000/api/devices/discover
   ```

### Genymotion

1. **Start Genymotion** emulator
2. **Note the IP address** from Genymotion settings
3. **Connect via ADB**:
   ```bash
   adb connect <genymotion-ip>:5555
   ```
4. **Register in Mobilicustos**:
   ```bash
   curl -X POST http://localhost:8000/api/devices \
     -H "Content-Type: application/json" \
     -d '{
       "name": "Genymotion Pixel",
       "device_type": "genymotion",
       "platform": "android",
       "connection_string": "<genymotion-ip>:5555"
     }'
   ```

### Corellium

1. **Obtain API key** from Corellium dashboard
2. **Configure in `.env`**:
   ```bash
   CORELLIUM_API_KEY=your-api-key
   CORELLIUM_DOMAIN=https://app.corellium.com
   ```
3. **Devices will be discovered automatically** when scanning

## Troubleshooting

### Services Won't Start

```bash
# Check for port conflicts
lsof -i :3000
lsof -i :8000
lsof -i :5432

# Reset and restart
docker compose down -v
docker compose up -d
```

### Database Connection Issues

```bash
# Check PostgreSQL is healthy
docker compose exec postgres pg_isready

# Check connection from API container
docker compose exec api python -c "from api.database import engine; print('OK')"
```

### Out of Disk Space

```bash
# Clean Docker resources
docker system prune -a

# Remove old analysis artifacts
docker compose exec api rm -rf /app/uploads/old-scans/*
```

## Updating

```bash
# Pull latest changes
git pull origin main

# Rebuild containers
docker compose build

# Restart with new images
docker compose up -d

# Run any database migrations
docker compose exec api alembic upgrade head
```

## Uninstalling

```bash
# Stop and remove containers, networks, volumes
docker compose down -v

# Remove images
docker compose down --rmi all

# Remove the directory
cd ..
rm -rf Mobilicustos
```
