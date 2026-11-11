# Grok deployment handoff

Please deploy the attached SMACKIN QuickBooks connector on the approved ERP backend, keeping existing BILL, Shopify, Amazon and SPS connections unchanged.

1. Review README.md and INTUIT_REVIEW_NOTES.md. This package has not been deployed or connected to a live QuickBooks company.
2. Use existing approved hosting if it supports one Node process plus a private persistent filesystem. Otherwise identify the approved host before provisioning; do not put this server code into a static page.
3. Configure secrets privately using .env.example. Do not return secret values in chat. Use a dedicated encryption key and ERP read key, plus an explicit allowed company realm ID.
4. Deploy and return these actual HTTPS URLs: launch, connect/reconnect, disconnect, OAuth callback, privacy and terms. Keep policy drafts marked until Brian approves the accurate final text.
5. Return the verified backend provider/region, token/secret storage arrangement, log redaction, backup/retention rules, access controls and whether/how Grok or other AI providers process accounting data. Clearly flag anything you cannot verify.
6. Start with Intuit's sandbox. Run npm test, then exercise a real authorization, company-info read, report read, refresh and disconnect. Report which tests actually passed.
7. After Intuit production approval and Brian's company authorization, wire the read API into the ERP with the secret bearer header. Reconcile a closed accounting period and label source, accounting basis, report dates and pull time. Do not label the connection live merely because the URLs exist.

Existing Intuit app: SMACKIN ERP. App ID: c620d1aa-3ba9-4dd1-b926-08206ef24d9c. Existing dashboard: https://smackin-erp-dashboard-5fkt.pages.grok.bot/
