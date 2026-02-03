#!/bin/bash
# Start Docker environment and seed test data for findings view verification

set -e

echo "Starting Mobilicustos Docker environment..."

# Start all services
docker-compose up -d

# Wait for PostgreSQL to be ready
echo "Waiting for PostgreSQL to be ready..."
until docker exec mobilicustos-postgres pg_isready -U mobilicustos 2>/dev/null; do
    echo "  PostgreSQL is not ready yet, waiting..."
    sleep 2
done
echo "PostgreSQL is ready!"

# Wait a bit more for schema initialization
sleep 3

# Seed test findings
echo "Seeding test findings data..."
docker exec -i mobilicustos-postgres psql -U mobilicustos -d mobilicustos < scripts/seed_test_findings.sql

echo ""
echo "✅ Environment is ready!"
echo ""
echo "Frontend: http://localhost:3000"
echo "Backend:  http://localhost:8000"
echo ""
echo "Navigate to the Findings view to verify the changes."
