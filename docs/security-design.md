# Security design decisions

- Keep state and replay receipts transactional; reject conflicting command keys.
- Derive tenant and roles exclusively from trusted identities.
- Compare independent reviewers by subject, including when one subject holds multiple roles.
- Preserve missing evidence, stale observations and unknown permissions as distinct outcomes.
- Scope exports and retain provenance instead of asserting external truth from a digest.
- Use private local files and exclusive writes for generated material.
- Keep cloud and third-party writes outside these demos.
- Pin CI actions by commit, limit workflow permissions to contents read and avoid persisted checkout credentials.
- Hash-lock Python dependencies and lock exact Node dependencies.

An export must not be represented as proven effective access. Malicious pagination must never redirect credentials to another host. A source-controlled scope string cannot select an arbitrary gateway destination. Keep the synthetic backend server-owned, reject excess scopes and bind native event deduplication to exact content.
