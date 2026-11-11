# SMACKIN QuickBooks setup package

Prepared November 11, 2026. **Created and locally tested source; not deployed, not authorized to a live QuickBooks company, and not an Intuit-approved production integration.** No live credentials or financial data are included.

## Found

| Item | Verified value |
|---|---|
| ERP dashboard / existing launch page | https://smackin-erp-dashboard-5fkt.pages.grok.bot/ |
| Dashboard host | smackin-erp-dashboard-5fkt.pages.grok.bot |
| Intuit app | SMACKIN ERP |
| App ID | c620d1aa-3ba9-4dd1-b926-08206ef24d9c |
| Intuit workspace | SMACKIN ERP, 9341458681366460 |
| Production keys | Locked behind app details and compliance in the observed portal |
| Hosting form | Intuit permits the business's operating country for cloud hosting when server location is unknown; fixed outbound IP is optional if unavailable. |

The public dashboard address does not establish its backend provider, data region, encryption, retention, or a working OAuth endpoint. No existing callback or ERP source repository was found in the locations checked. Grok Bot's installed app version does not match the supported automation adapter, so no message was sent to Grok.

## Created

This dependency-free Node service implements a single-company QuickBooks connection, browser-bound one-use OAuth state, AES-256-GCM token storage, refresh-token rotation, explicit revocation, and an authenticated read API. Public policy pages are visibly drafts until reviewed. OAuth credentials remain on the server. It has no accounting write/payment routes.

This is intentionally a **single-process** service with a private persistent filesystem. It is not suitable for stateless edge hosting or multiple replicas without replacing storage and locks with shared transactional infrastructure. Do not copy it into a static Grok page and assume the callback works.

## Deployment and Intuit URLs

Deploy on SMACKIN's approved server/container host with a persistent private data directory and HTTPS reverse proxy. Use the same existing ERP backend if it supports Node and durable storage. No hosting account or paid service has been purchased or configured.

`CONNECTOR_ORIGIN` below means the actual deployed HTTPS origin. These are route mappings, **not currently live URLs**.

| Intuit field | Value after deployment |
|---|---|
| Host domain | Host portion of the deployed connector origin, without `https://` |
| Launch URL | `CONNECTOR_ORIGIN/` (links to the existing ERP dashboard) |
| Connect / reconnect URL | `CONNECTOR_ORIGIN/quickbooks/connect` |
| Disconnect URL | `CONNECTOR_ORIGIN/quickbooks/disconnect` |
| OAuth redirect URI | `CONNECTOR_ORIGIN/quickbooks/callback` |
| Privacy policy URL | `CONNECTOR_ORIGIN/privacy`, only after draft review |
| End-user license agreement URL | `CONNECTOR_ORIGIN/terms`, only after draft review |

Do not register a made-up hostname, use the static dashboard as a callback, or submit the draft policies as effective policies. The callback route is distinct from launch and connect/reconnect.

## Configure and run

1. Use Node 22 or newer. There are no third-party runtime dependencies. Run `npm test`.
2. Configure the names in `.env.example` using the host's secret manager. Node does not automatically load that template. On a protected local sandbox, Node can load a private untracked `.env` with `node --env-file=.env server.mjs`.
3. Generate independent cryptographic secrets for `TOKEN_ENCRYPTION_KEY_BASE64` (32 bytes, base64) and `ERP_READ_KEY` (32 bytes, base64url). Store them directly in the host's secret manager. Never paste secrets into chat, URLs, source, policy pages or build logs.
4. Set `ADMIN_PASSWORD_SCRYPT` using `scripts/hash-password.mjs`, which accepts a unique password of at least 20 characters through stdin and outputs a salted scrypt hash. Supply the password without command-line arguments or shell-history exposure. Use a separate secret-manager password for this dedicated admin login.
5. Set `QBO_ENV=sandbox` first. Configure development client ID/secret and the exact allowed sandbox company realm ID. Production requires the production credentials and the exact SMACKIN production realm ID. Connection fails closed when credentials or the allowed company ID are missing.
6. Set `PUBLIC_ORIGIN` to the actual origin; register the exact callback URI in the matching Intuit environment. Use loopback HTTP only for sandbox development. Production refuses HTTP.
7. Start one instance with `npm start`. The default listener is `127.0.0.1:3000`, suitable behind a same-host HTTPS proxy. Set `HOST=0.0.0.0` only when the host's private container/network boundary requires it and the service is protected by that boundary.
8. Configure the proxy to avoid logging query strings, cookies, Authorization headers, request/response bodies or OAuth codes. Never expose the `DATA_DIR`; keep it outside the web root. Apply host access controls, secret management, backups, retention, patching and monitoring before production.
9. Open `/quickbooks/connect`, sign in as the administrator and authorize the allowed company. The callback exchanges the code server-side and redirects away from the query string.
10. Verify sandbox behavior, deploy the approved policy text, confirm the security evidence checklist, then complete Intuit's production application. Once approved, authorize production and compare a known closed-period report against QuickBooks.

The service uses HTTP Basic authentication for its dedicated admin pages, over HTTPS in production. This is separate from QuickBooks login. The browser may retain the admin credential until it is closed. For a shared deployment, put the admin routes behind company SSO/MFA and adapt the server's authorization accordingly before broadening access.

The persistent `connector.lock` prevents a second process from using the same token file. Following a crash, verify the prior process is stopped before manually removing that lock. In-memory browser sessions expire after 15 minutes and are lost on restart; restart the connection flow if necessary. Only one instance may own the token store.

## Read API for Grok

Send `Authorization: Bearer <ERP_READ_KEY>` only over HTTPS to the connector. This grants read access to sensitive company accounting data; store it in Grok's approved secret store. No route returns the underlying Intuit tokens.

| Route | Purpose |
|---|---|
| `GET /api/company` | Company information / initial test |
| `GET /api/reports/ProfitAndLoss` | P&L |
| `GET /api/reports/BalanceSheet` | Balance sheet |
| `GET /api/reports/CashFlow` | Cash flow |
| `GET /api/entities/Invoice` | Invoices / receivables source |
| `GET /api/entities/Bill` | Bills / payables source |
| `GET /api/entities/Customer` | Customers |
| `GET /api/entities/Vendor` | Vendors |
| `GET /api/entities/Account` | Chart of accounts |
| `GET /api/entities/Payment` | Customer payments |
| `GET /api/entities/BillPayment` | Bill payments |
| `GET /api/entities/Purchase` | Purchases |
| `GET /api/entities/JournalEntry` | Journal entries |
| `GET /api/entities/SalesReceipt` | Sales receipts |
| `GET /api/entities/CreditMemo` | Customer credits |

Reports accept only `start_date`, `end_date` (ISO dates), `accounting_method` (`Cash` or `Accrual`) and `summarize_column_by` (`Total`, `Month`, `Quarter`, `Year`). Report-specific combinations must be checked in the Intuit sandbox. Entity lists support `start` (1-based) and `limit` (1–1000); paginate until fewer than `limit` records return. Transaction date filters/incremental synchronization, normalized ERP tables, AR/AP aging calculations, retries with backoff and a recurring pull job are **not implemented** in this package.

Intuit's accounting OAuth scope is not intrinsically read-only. Read-only behavior is enforced by this service's GET allowlist. Possession of the raw Intuit tokens could permit broader actions; therefore tokens are never delivered to the ERP caller.

401 responses from the vendor prompt reconnection; rate limits return 429. This service does not blindly retry ambiguous token exchanges or revocation requests. A failed revoke keeps the local token file for operator follow-up and does not falsely report a completed disconnect.

## Sources checked

- Intuit OAuth flow, state, exchange, refresh and revocation: https://static.developer.intuit.com/output_html/qbo/docs/develop/authentication-and-authorization/oauth-2.0.html
- Intuit OAuth FAQ and callback requirements: https://static.developer.intuit.com/output_html/qbo/docs/develop/authentication-and-authorization/faq.html
- Intuit staff response on internal apps, AES and HTTPS callbacks: https://help.developer.intuit.com/s/question/0D5TR00001aDrOS0A0/my-private-quickbooks-online-apps-production-credentials-are-blocked-by-compliance-do-aes-token-encryption-and-http-302-oauth-callback-requirements-apply-to-internalonly-google-apps-script-integrations
- App requirements and hosting form: observed in the signed-in SMACKIN ERP Intuit Developer portal on November 11, 2026.
