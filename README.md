# SOCForge

Evidence-first security operations workbench for SOC investigation and automation.

## Project goal

SOCForge is designed to reduce repetitive L1/L2 SOC analyst work while
preserving evidence, traceability, and human control.

## Core principle

Evidence first → automation second → AI assistance third.

## Planned workflow

Elastic alert
    ↓
Event parsing
    ↓
Normalization
    ↓
Entity extraction
    ↓
Correlation
    ↓
Threat intelligence
    ↓
MITRE ATT&CK mapping
    ↓
Risk/confidence scoring
    ↓
Investigation timeline
    ↓
Case report

## Initial integrations

- Elastic Security / Elasticsearch
- MITRE ATT&CK
- Threat intelligence sources

## Initial investigation playbooks

- Suspicious PowerShell
- Brute-force/authentication anomaly
- Malicious IP
- Suspicious login
- Malicious file hash

## Technology

- Python
- FastAPI
- PostgreSQL
- Elasticsearch
- Next.js
- Docker
- pytest

## Development status

Early development / foundation phase.
