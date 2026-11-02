# IntegrationGuard architecture

Observations retain source identity, timestamp, digest, previous snapshot digest and explicit unknown settings. Findings point to exact normalized fields. Corrections require the current record version and fresh replacement evidence; they do not write to the provider. Event deduplication binds native identifier, integration and event content and rejects conflicting reuse. The local gateway permits one synthetic count resource, a server-owned loopback destination and exactly synthetic:read scope. It disables environment proxies and redirects, bounds replies, records successful read evidence and limits an identity to five requests per minute. A separate executable local receiver verifies a domain-separated HMAC, deduplicates delivery content and independently reads back its persisted receipt.

## Domain sequence

Read-only export --> Field-specific findings --> Correction evidence --> Normalized event --> Signed local receiver

## Consistency and recovery

`app/domain.py` owns explicit schemas and domain transitions. `app/service.py` validates input and commits state, audit entry and idempotency receipt in one SQLite transaction with `BEGIN IMMEDIATE`. `app/api.py` authenticates server-owned identities, limits request bytes and exposes scoped operations. `app/cli.py` executes the committed scenario against the same service. `web/` validates the scenario contract and renders real API results without HTML interpolation.

A process crash before commit rolls back domain state and receipts. Local filesystem effects in the certificate authority are separate from SQLite and partial CA initialization fails closed. Container state is disposable. Persistence, backups, independent audit checkpoints and external identity lifecycle are deployment responsibilities.

## Explicit scope

No Salesforce or Vanta account was available for native acceptance. Salesforce collector contract tests use synthetic HTTP responses; they are not account verification. Its native query covers PermissionSet definitions only, not assignments, muting, MFA, connected applications or proven effective permissions. OAuth scopes in the assessment come from explicit imported observations. There is no native MuleSoft connector. The gateway and event receiver are actual loopback services using synthetic data, not live enterprise integrations. The receiver is not a commercial SIEM. Provider corrections are proposed by evidence only, never automatically executed. Rate windows are process-local.

Immutable observation snapshots retain correction history. A correction links to its previous digest and stores replacement source evidence before updating the current view. The offline CLI additionally sends normalized events over actual loopback HTTP to a signed, durable local receiver and checks signature rejection, delivery replay and independent persisted readback.
