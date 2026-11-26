# ORION Ledger Verify (`@aisynapse/orion-ledger-verify`)

**Zero-dependency, vendor-independent CLI verifier for ECDSA P-256 + SHA-256 hash-chained AI audit trails**, aligned with **EU AI Act (Regulation EU 2024/1689) Articles 12, 19(1), 26(6), and 73**.

Published as an open verification utility by **[AI Synapse Technologies, S.L.U.](https://aisynapse.tech)** — architects of **[ORION Trust OS](https://orion.aisynapse.tech)** and led by **[Alejandro Fabián](https://alejandrofabian.aisynapse.tech)**.

## Why Vendor-Independent Audit Verification Matters
Under **Article 12** (automatic logging) and **Article 26(6)** (minimum 6-month retention under the deployer's direct control, extended by DORA or national law), European Public Administrations (AAPP) and regulated enterprises must prove what an AI system decided — and which signed policies governed it — **without depending on a SaaS vendor's mutable dashboard**.

This open-source CLI lets any CISO, DPO, external auditor, or supervisory authority (such as **AESIA**) cryptographically verify an exported audit ledger offline:
- **Hash-Chain Continuity (SHA-256):** Detects deleted, inserted, or reordered execution records.
- **Canonical Payload Integrity:** Detects any post-hoc edit to verdicts, FRIA IDs, PolicyBundle hashes, or timestamps.
- **Non-Repudiation (ECDSA P-256):** Verifies every receipt against the deployer's sovereign public key (`deployerPublicKeyPem`).

## Quick Start (Node.js 18+, Zero Dependencies)

```bash
# Clone the repository
git clone https://github.com/Jarvisfabix/orion-ledger-verify.git
cd orion-ledger-verify

# Verify the included signed reference bundle
node ./bin/orion-verify.mjs ./examples/sample-chain.json

# Generate a fresh signed sample chain with ephemeral P-256 keys
node ./bin/orion-verify.mjs --generate-sample ./examples/sample-chain.json
```

## Learn More
- **ORION Trust OS (Unified 9-Gate Sovereign AI Governance OS):** https://orion.aisynapse.tech
- **Free Interactive EU AI Act Art. 27 FRIA Checklist & Generator:** https://orion.aisynapse.tech/fria-art-27/
- **Position Paper 03 — Audit Trail Requirements (Art. 12, 19(1) & 26(6)):** https://aisynapse.tech/insights/audit-trail-art12-eu-ai-act/
- **EU AI Act Sovereign Glossary:** https://aisynapse.tech/glossary/
- **Chief Architect & Founder:** https://alejandrofabian.aisynapse.tech

## License
MIT © 2026 AI Synapse Technologies, S.L.U. (NIF ES-B88734611 · Barcelona, European Union)
