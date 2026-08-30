# Zero-Trust Infrastructure Controller

**Never trust. Always verify. Continuously enforce.**

A GitHub-ready security engineering reference implementation that evaluates identity, device posture, infrastructure configuration and workload risk before allowing infrastructure operations.

## Features
- FastAPI policy decision API
- Identity + MFA + device posture checks
- YAML policy-as-code
- Explainable risk scoring
- Kubernetes security analyzer
- Docker security analyzer
- Terraform security analyzer
- PostgreSQL audit trail
- Prometheus metrics
- Docker Compose deployment
- Kubernetes manifests
- CI + Trivy container scanning
- Unit tests and demo payloads
  <img width="1536" height="1024" alt="Zero-Trust Infrastructure Controller" src="https://github.com/user-attachments/assets/7d7a2ee0-d2ef-45c7-a592-d3daf5714cb5" />
## Architecture
```text
Request -> Identity/Device -> Policy Engine -> Infrastructure Analyzer
       -> Risk Engine -> ALLOW / AUDIT / APPROVAL / DENY -> Audit Log
```
## Decision thresholds
| Score | Decision |
|---:|---|
| 0-20 | ALLOW |
| 21-50 | AUDIT |
| 51-80 | APPROVAL |
| 81+ | DENY |

## Quick start
```bash
cp .env.example .env
docker compose up --build
```
Open `http://localhost:8000/docs`.

Demo:
```bash
curl -X POST http://localhost:8000/api/v1/evaluate \
  -H 'Authorization: Bearer dev-token' \
  -H 'Content-Type: application/json' \
  --data @examples/denied-request.json
```

## API
- `GET /health`
- `GET /ready`
- `GET /metrics`
- `GET /api/v1/policies`
- `POST /api/v1/evaluate`
- `POST /api/v1/analyze/kubernetes`
- `POST /api/v1/analyze/docker`
- `POST /api/v1/analyze/terraform`
- `GET /api/v1/audit`

## Security note
The development bearer token is intentionally simple. For production, integrate OIDC/JWT validation, a real device-posture provider, secret management, certificate-based service identity and an external immutable audit/SIEM destination.

## Project structure
```text
controller/       API, policy, risk, persistence, analyzers
policies/         policy-as-code
examples/         demo requests
tests/            automated tests
kubernetes/       deployment manifests
docs/             architecture and threat model
.github/          CI/security automation
```

## License
Apache-2.0.0
