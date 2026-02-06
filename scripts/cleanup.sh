#!/usr/bin/env bash
# Mobilicustos Cleanup Script
# Removes Docker containers, images, volumes, databases, and networks.
#
# Usage:
#   ./scripts/cleanup.sh [OPTIONS]
#
# Options:
#   --all          Remove everything (containers, images, volumes, db, networks)
#   --containers   Stop and remove containers
#   --images       Remove Docker images
#   --volumes      Remove persistent data volumes
#   --db           Drop and recreate the database schema
#   --networks     Remove Docker networks
#   --force        Skip confirmation prompts
#   --help         Show this help message

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Project settings
PROJECT_NAME="mobilicustos"
COMPOSE_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/docker-compose.yml"
POSTGRES_CONTAINER="${PROJECT_NAME}-postgres"
POSTGRES_USER="${POSTGRES_USER:-mobilicustos}"
POSTGRES_DB="${POSTGRES_DB:-mobilicustos}"

# Flags
DO_CONTAINERS=false
DO_IMAGES=false
DO_VOLUMES=false
DO_DB=false
DO_NETWORKS=false
FORCE=false

info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; }

usage() {
    echo -e "${BOLD}Mobilicustos Cleanup Script${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --all          Remove everything (containers, images, volumes, db, networks)"
    echo "  --containers   Stop and remove containers"
    echo "  --images       Remove Docker images"
    echo "  --volumes      Remove persistent data volumes (PostgreSQL, Neo4j, Redis)"
    echo "  --db           Drop and recreate the database schema"
    echo "  --networks     Remove Docker networks"
    echo "  --force        Skip confirmation prompts"
    echo "  --help         Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --containers              # Stop and remove containers only"
    echo "  $0 --all                     # Full cleanup (with confirmation)"
    echo "  $0 --all --force             # Full cleanup (no confirmation)"
    echo "  $0 --volumes --db            # Reset data only"
}

confirm() {
    if [ "$FORCE" = true ]; then
        return 0
    fi
    local msg="$1"
    echo -en "${YELLOW}${msg} [y/N]: ${NC}"
    read -r response
    case "$response" in
        [yY][eE][sS]|[yY]) return 0 ;;
        *) return 1 ;;
    esac
}

cleanup_containers() {
    info "Stopping and removing containers..."
    if docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" down 2>/dev/null; then
        success "Containers stopped and removed"
    else
        # Try without project flag
        if docker compose -f "$COMPOSE_FILE" down 2>/dev/null; then
            success "Containers stopped and removed"
        else
            warn "No containers to remove or docker compose not available"
        fi
    fi

    # Also remove any orphaned containers with the project prefix
    local orphans
    orphans=$(docker ps -a --filter "name=${PROJECT_NAME}" --format '{{.Names}}' 2>/dev/null || true)
    if [ -n "$orphans" ]; then
        info "Removing orphaned containers..."
        echo "$orphans" | while read -r name; do
            docker rm -f "$name" 2>/dev/null && success "Removed: $name" || true
        done
    fi
}

cleanup_images() {
    info "Removing Docker images..."
    if docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" down --rmi all 2>/dev/null; then
        success "Images removed"
    else
        if docker compose -f "$COMPOSE_FILE" down --rmi all 2>/dev/null; then
            success "Images removed"
        else
            warn "No images to remove"
        fi
    fi

    # Remove any dangling images from builds
    local dangling
    dangling=$(docker images -f "dangling=true" -q 2>/dev/null || true)
    if [ -n "$dangling" ]; then
        info "Removing dangling images..."
        docker rmi $dangling 2>/dev/null || true
        success "Dangling images cleaned"
    fi
}

cleanup_volumes() {
    info "Removing persistent data volumes..."
    local volumes=("${PROJECT_NAME}_postgres_data" "${PROJECT_NAME}_neo4j_data" "${PROJECT_NAME}_redis_data")
    for vol in "${volumes[@]}"; do
        if docker volume inspect "$vol" &>/dev/null; then
            docker volume rm "$vol" 2>/dev/null && success "Removed volume: $vol" || warn "Could not remove: $vol (in use?)"
        else
            info "Volume not found: $vol (already removed)"
        fi
    done

    # Clean up uploads and reports directories
    local project_root
    project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    if [ -d "$project_root/uploads" ]; then
        info "Cleaning uploads directory..."
        rm -rf "$project_root/uploads/"* 2>/dev/null || true
        success "Uploads cleaned"
    fi
    if [ -d "$project_root/reports" ]; then
        info "Cleaning reports directory..."
        rm -rf "$project_root/reports/"* 2>/dev/null || true
        success "Reports cleaned"
    fi

    # Clean temp analyzer directory
    if [ -d "/tmp/mobilicustos_analyzer" ]; then
        info "Cleaning analyzer temp directory..."
        rm -rf /tmp/mobilicustos_analyzer/* 2>/dev/null || true
        success "Analyzer temp cleaned"
    fi
}

cleanup_db() {
    info "Resetting database..."
    # Check if postgres container is running
    if ! docker ps --format '{{.Names}}' | grep -q "$POSTGRES_CONTAINER"; then
        warn "PostgreSQL container is not running. Starting it..."
        docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" up -d postgres 2>/dev/null || true
        info "Waiting for PostgreSQL to be ready..."
        sleep 5
    fi

    # Drop and recreate schema
    if docker exec "$POSTGRES_CONTAINER" psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public; GRANT ALL ON SCHEMA public TO $POSTGRES_USER;" 2>/dev/null; then
        success "Database schema reset"
    else
        error "Failed to reset database schema"
        warn "You may need to remove the volume instead: $0 --volumes"
    fi

    # Clear Neo4j data
    info "Clearing Neo4j data..."
    local neo4j_container="${PROJECT_NAME}-neo4j"
    if docker ps --format '{{.Names}}' | grep -q "$neo4j_container"; then
        if docker exec "$neo4j_container" cypher-shell -u "${NEO4J_USER:-neo4j}" -p "${NEO4J_PASSWORD:-changeme}" "MATCH (n) DETACH DELETE n" 2>/dev/null; then
            success "Neo4j data cleared"
        else
            warn "Could not clear Neo4j data"
        fi
    else
        warn "Neo4j container not running, skipping"
    fi

    # Flush Redis
    info "Flushing Redis..."
    local redis_container="${PROJECT_NAME}-redis"
    if docker ps --format '{{.Names}}' | grep -q "$redis_container"; then
        if docker exec "$redis_container" redis-cli FLUSHALL 2>/dev/null; then
            success "Redis flushed"
        else
            warn "Could not flush Redis"
        fi
    else
        warn "Redis container not running, skipping"
    fi
}

cleanup_networks() {
    info "Removing Docker networks..."
    local networks=("${PROJECT_NAME}_mobilicustos" "${PROJECT_NAME}_default")
    for net in "${networks[@]}"; do
        if docker network inspect "$net" &>/dev/null; then
            docker network rm "$net" 2>/dev/null && success "Removed network: $net" || warn "Could not remove: $net (in use?)"
        else
            info "Network not found: $net (already removed)"
        fi
    done
}

# Parse arguments
if [ $# -eq 0 ]; then
    usage
    exit 0
fi

while [ $# -gt 0 ]; do
    case "$1" in
        --all)
            DO_CONTAINERS=true
            DO_IMAGES=true
            DO_VOLUMES=true
            DO_DB=true
            DO_NETWORKS=true
            ;;
        --containers)  DO_CONTAINERS=true ;;
        --images)      DO_IMAGES=true ;;
        --volumes)     DO_VOLUMES=true ;;
        --db)          DO_DB=true ;;
        --networks)    DO_NETWORKS=true ;;
        --force)       FORCE=true ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
    shift
done

# Summary of actions
echo ""
echo -e "${BOLD}Mobilicustos Cleanup${NC}"
echo -e "${BOLD}====================${NC}"
echo ""
echo "Actions to perform:"
[ "$DO_CONTAINERS" = true ] && echo -e "  ${CYAN}*${NC} Stop and remove containers"
[ "$DO_DB" = true ]         && echo -e "  ${CYAN}*${NC} Reset databases (PostgreSQL, Neo4j, Redis)"
[ "$DO_IMAGES" = true ]     && echo -e "  ${CYAN}*${NC} Remove Docker images"
[ "$DO_VOLUMES" = true ]    && echo -e "  ${CYAN}*${NC} Remove persistent volumes"
[ "$DO_NETWORKS" = true ]   && echo -e "  ${CYAN}*${NC} Remove Docker networks"
echo ""

if ! confirm "Proceed with cleanup?"; then
    info "Cleanup cancelled"
    exit 0
fi

echo ""

# Execute in order: db first (needs running containers), then containers, images, volumes, networks
[ "$DO_DB" = true ]         && cleanup_db
[ "$DO_CONTAINERS" = true ] && cleanup_containers
[ "$DO_IMAGES" = true ]     && cleanup_images
[ "$DO_VOLUMES" = true ]    && cleanup_volumes
[ "$DO_NETWORKS" = true ]   && cleanup_networks

echo ""
success "Cleanup complete!"
echo ""
echo -e "To start fresh: ${CYAN}docker compose -f $COMPOSE_FILE up -d${NC}"
