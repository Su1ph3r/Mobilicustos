# Contributing to Mobilicustos

Thank you for your interest in contributing to Mobilicustos! This document provides guidelines and information for contributors.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone.

## How to Contribute

### Reporting Bugs

Before creating a bug report, please check existing issues to avoid duplicates.

When filing a bug report, include:
- A clear, descriptive title
- Steps to reproduce the issue
- Expected vs actual behavior
- Environment details (OS, Docker version, browser)
- Relevant logs or screenshots

### Suggesting Features

Feature requests are welcome! Please:
- Check existing issues and discussions first
- Clearly describe the use case
- Explain why this would benefit most users
- Consider implementation complexity

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Follow coding standards** (see below)
3. **Write tests** for new functionality
4. **Update documentation** as needed
5. **Ensure all tests pass** before submitting
6. **Write a clear PR description** explaining your changes

## Development Setup

### Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- Node.js 18+ (for frontend development)
- Python 3.11+ (for backend development)

### Local Development

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/Mobilicustos.git
cd Mobilicustos

# Copy environment file
cp .env.example .env

# Start development services
docker compose up -d postgres neo4j redis

# Backend development
cd api
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
uvicorn api.main:app --reload

# Frontend development (separate terminal)
cd frontend
npm install
npm run dev
```

### Running Tests

```bash
# Backend tests
cd api
pytest -v

# Frontend tests
cd frontend
npm test

# E2E tests
npm run test:e2e
```

## Coding Standards

### Python (Backend)

- Follow PEP 8 style guide
- Use type hints
- Write docstrings for public functions
- Format with `black` and `isort`
- Lint with `ruff`

```python
# Good
async def get_findings(
    severity: str | None = None,
    limit: int = 100,
) -> list[Finding]:
    """Retrieve findings with optional filtering.

    Args:
        severity: Filter by severity level
        limit: Maximum results to return

    Returns:
        List of Finding objects
    """
    ...
```

### TypeScript/Vue (Frontend)

- Use TypeScript for all new code
- Follow Vue 3 Composition API patterns
- Use PrimeVue components consistently
- Format with Prettier
- Lint with ESLint

```vue
<script setup lang="ts">
import { ref, computed } from 'vue'
import type { Finding } from '@/types'

const props = defineProps<{
  finding: Finding
}>()

const severityClass = computed(() => `severity-${props.finding.severity}`)
</script>
```

### Commit Messages

Use clear, descriptive commit messages:

```
Add severity filtering to findings view

- Implement severity quick-filter buttons
- Add count badges for each severity level
- Update store to track active filters
```

**Do NOT include:**
- References to AI assistance
- Co-authored-by lines for automated tools

## Project Structure

```
mobilicustos/
├── api/                 # FastAPI backend
│   ├── routers/        # API endpoints
│   ├── services/       # Business logic
│   ├── models/         # Pydantic schemas
│   └── tests/          # Backend tests
├── frontend/           # Vue.js frontend
│   ├── src/
│   │   ├── components/ # Reusable components
│   │   ├── views/      # Page components
│   │   ├── stores/     # Pinia stores
│   │   └── types/      # TypeScript types
│   └── tests/          # Frontend tests
├── report-processor/   # Finding normalization
├── knowledge-base/     # Remediation guidance
└── docs/              # Documentation
```

## Adding New Tools

To add a new analysis tool:

1. Create analyzer in `api/services/analyzers/`
2. Define output parser in `report-processor/parsers/`
3. Add tool configuration to `api/config.py`
4. Update Dockerfile if new dependencies needed
5. Write tests and documentation

See [docs/TOOLS.md](docs/TOOLS.md) for detailed guidance.

## Questions?

- Open a GitHub Discussion for general questions
- Check existing documentation in `/docs`
- Review closed issues for similar topics

Thank you for contributing!
