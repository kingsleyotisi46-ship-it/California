# California Bank

California Bank is being migrated from a static preview-only interface to a Node.js and PostgreSQL application hosted on Render.

## Included in this first backend migration

- Argon2id password hashing, session rotation at sign-in, PostgreSQL-backed sessions, HttpOnly/SameSite cookies, CSRF validation, request rate limits, security headers, input validation, and audit events.
- PostgreSQL migrations for users, password-reset token storage, provider-linked customers/accounts/transactions, idempotency keys, webhook deduplication, and security audit records.
- USD-only account model. Money is represented in integer cents; balances and transactions are not generated locally.
- Unit selected as the banking infrastructure integration candidate. Unit is a financial technology platform, not a bank; banking services depend on partner banks and an approved program.
- Money movement intentionally disabled. Approved program credentials, onboarding/KYC, provider payment endpoints, webhook signature verification, and reconciliation must be implemented and tested before enabling money movement.
- No fake customer records, sample balances, fake card numbers, or simulated successful transfers are seeded.

## Deploy to Render

1. Push this repository to GitHub.
2. In Render, create a new Blueprint from this repository and review render.yaml.
3. Set APP_ORIGIN to the deployed HTTPS origin. Keep UNIT_PROGRAM_ENABLED=false until Unit and its partner bank approve the program and the integration passes compliance and security review.
4. Store provider secrets only in Render's secret environment settings. Never commit API tokens or production customer data.
5. Verify /healthz, authentication, session persistence, migration logs, and backup/restore procedures.

## Local development

Requirements: Node.js 22+ and PostgreSQL.

1. Copy .env.example to .env and set a strong random SESSION_SECRET.
2. Create a local PostgreSQL database and set DATABASE_URL.
3. Run npm install, npm run migrate, then npm start.
4. Visit http://localhost:3000.

## Production readiness gates

This repository is an initial secure backend foundation, not authorization to operate a bank. Before any real-money launch, obtain a banking program agreement and partner-bank approval; complete legal, compliance, AML/BSA, sanctions, KYC/CIP, privacy, disclosures, complaint handling, dispute handling, and operational controls. Implement and test approved provider application/customer/account/payment endpoints and official webhook verification. Implement verified email delivery and a complete password-reset flow; the token table exists but no reset endpoint is exposed yet. Add MFA, account recovery controls, monitoring, security testing, dependency scanning, encrypted backups, incident response, and retention policies. Run provider sandbox integration tests, then separate production certification and bank/provider approval. Do not represent sandbox data as real funds.

## Provider references

- Unit API overview: https://www.unit.co/docs/api/
- Unit quickstart: https://www.unit.co/docs/api/quickstart/
- Unit accounts overview: https://www.unit.co/docs/api/accounts/overview/

Unit's documentation explains that accounts are created under customers, money movement requires provider payment resources, and account limits and terms are agreed within the partner-bank program. Production credentials and capabilities are provisioned through program onboarding.