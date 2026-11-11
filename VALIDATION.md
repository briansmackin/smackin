# Validation — November 11, 2026

Node v24.22.1; 12 automated tests passed, zero failures.

Covered token encryption and tamper rejection; HTTP production refusal; admin/API authentication; draft policy labels; CSRF and browser-bound state; expiration and replay; allowed company enforcement; encrypted persistence; write and arbitrary-query rejection; report date validation; concurrent refresh and token rotation; safe disconnect; failed revoke preservation; and single-process locking.

Vendor responses were mocked. No live Intuit credentials, real accounting data or production authorization was used. No public deployment, Intuit compliance approval, real TLS edge validation, live refresh/revocation, ERP ingestion or browser visual QA is claimed.

The source is a deployment starting point, not an independently audited or approved production service. See INTUIT_REVIEW_NOTES.md for the remaining checks.
