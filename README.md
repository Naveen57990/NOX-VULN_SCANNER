# Vulnerability Scanner

## Project Structure

```
vuln_scanner/
├── main.py              # Entry point
├── config/              # Configuration
├── orchestrator/        # Scan orchestration
├── tools/               # Security tools
├── ai/                  # AI analysis
├── memory/              # Storage
└── reports/             # Report generation
```

## Quick Start

```bash
# Docker
docker build -t vuln-scanner .
docker run --rm vuln-scanner --url https://example.com

# Local
pip install -r vuln_scanner/requirements.txt
python vuln_scanner/main.py --url https://example.com
```

## GitHub Actions

Push to trigger workflow_dispatch, then manually run with target URL.

## Environment Variables

- `OPENAI_API_KEY` / `ANTHROPIC_API_KEY`: AI analysis
- `AUTHORIZED_TARGETS`: Allowed targets
- `VERBOSE`: Debug output
