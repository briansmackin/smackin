# Intuit production application: evidence and unresolved answers

As of November 11, 2026. This is a preparation worksheet, not a submitted or approved security attestation.

## Known app description

SMACKIN ERP is a private internal reporting and operations application for Smackin', Inc. Its planned direct QuickBooks Online integration reads company accounting records and reports for reconciliation and management dashboards. It is not offered to outside customers and is not intended to initiate payments or write accounting entries.

The app is SMACKIN ERP, App ID `c620d1aa-3ba9-4dd1-b926-08206ef24d9c`. The existing dashboard is `https://smackin-erp-dashboard-5fkt.pages.grok.bot/`. Production credentials were locked behind required app details and the compliance questionnaire when inspected.

## Answers supported by this code, conditional on deploying this version

| Topic | Implemented behavior | Evidence limit |
|---|---|---|
| Token storage | AES-256-GCM; random IV per write; key separate from ciphertext | Host secret storage and backups are not configured or verified |
| OAuth state | Random state tied to an HttpOnly browser session; expiry; one use | Synthetic local tests, no live Intuit test |
| Redirect | Exact configured callback; server-side exchange; HTTP 302 to a clean path | Real HTTPS hostname and proxy are not deployed |
| Allowed company | Explicit configured company ID; mismatch rejected before exchange | Real production realm ID still needed |
| Data operations | Fixed read routes; accounting API requests use GET only | Intuit accounting OAuth scope itself can grant writes |
| Refresh | Serialized renewal and atomic encrypted token replacement | Single process only; live refresh behavior untested |
| Disconnect | Authenticated POST with CSRF; vendor revocation before local token removal | Live Intuit revocation not tested; exported ERP data is separate |
| Logs | Application does not log request URLs, headers, bodies or tokens | Reverse proxy/platform logs need explicit configuration |
| API caller | Separate bearer secret for Grok's read requests | Secret storage, rotation and authorized personnel are not verified |
| Admin login | Dedicated password hash; HTTPS; basic attempt throttling | No SSO/MFA in this standalone package; host access policy needed |

## Must be verified before submission

- Actual backend provider, persistent storage location, region and responsible administrator. The static dashboard hostname is not proof of these.
- Who can access source, deployments, secrets, financial results and backups; MFA/access removal policies.
- TLS at the public edge; protected internal listener; query-string and credential logging disabled throughout the request path.
- Retention and deletion of exports, backups and logs; incident process and notification contacts.
- Actual Grok/AI processing, approved subprocessors, model-training settings and contractual data use. Do not answer “no AI” merely because this connector itself does not call an AI model.
- Whether this app is used in any industry Intuit lists as regulated. Select based on the actual questionnaire; the company is a snack manufacturer/brand.
- Production credentials, allowed company ID and successful sandbox/live tests.
- Privacy/EULA owner review, accurate effective date, actual contact channel, and public availability at the deployed URLs.
- Developer-profile email verification.

Do not mark unverified organization-wide controls as implemented solely because a code file exists. Do not submit a compliance declaration until the app owner has reviewed its concrete answers.
