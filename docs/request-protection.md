# Request protection and bootstrap credentials

Fresh installs continue to accept `admin` / `admin` for initial login. The
backend compares the configured bcrypt hash with `admin` at startup, including
existing installations: it does not rely on a new state-file flag or on a
particular bcrypt salt. A non-default initial password does not require rotation.

## Login/UI contract

`POST /api/v1/auth/login` retains `access_token`, `token_type`, and `expires_at`,
and adds a boolean `requires_password_change` (always present).

When true, use the returned Bearer token only for:

- `POST /api/v1/auth/password` with `current_password` and `new_password`;
- `GET /api/v1/system/status` for authenticated diagnostic status.

All other protected routes, including management reads/downloads, return HTTP
403 with `{"error":"password change required","requires_password_change":true}`.
Public health/login remain available. The UI must show the password-change form
instead of loading management data when the login flag is true.

A successful password change returns 204 and durably invalidates **all** previous
JWTs, including the bootstrap token. Discard the token and log in again with the
new password; `requires_password_change` will be false. Existing password rules
remain: 8..72 bytes. Passwords are persisted to the existing mode-0600
`admin-password.hash` override; no state migration is needed. Old credentials
cannot be restored merely by restarting with the installer's original hash.

## Admission limits

The following environment values work in the existing env file or process
environment (process environment takes precedence). Missing values use defaults;
invalid, zero, negative, and excessive values fail startup rather than disabling
protection.

| Variable | Default | Allowed range | Scope |
| --- | ---: | --- | --- |
| `GOVPN_API_MAX_CONCURRENT` | 32 | 1..1024 | All requests except public GET health |
| `GOVPN_API_REQUESTS_PER_MINUTE` | 300 | 1..100000 | Each verified Bearer token, all protected requests |
| `GOVPN_API_MAINTENANCE_MAX_CONCURRENT` | 1 | 1..32 | Tune and reconcile combined, server-wide |
| `GOVPN_API_MAINTENANCE_PER_MINUTE` | 2 | 1..1000 | Tune and reconcile combined, per verified token |

Maintenance routes are `POST /api/v1/system/tune` and
`POST /api/v1/system/reconcile`. They consume both ordinary and maintenance
budgets. Limits use fixed one-minute windows beginning with the first accepted
request. Concurrency admission is nonblocking: overload returns HTTP 429 with
integer-seconds `Retry-After` (1 for concurrency, remaining window for rate), not
an unbounded waiting queue. Clients should honor this header; do not auto-retry
mutating requests blindly. `GET /api/v1/health` bypasses admission limits.

Rate state is keyed by SHA-256 of the verified token (not raw credentials),
bounded at 10,000 identities. Expired entries are reclaimed at saturation; a full
table rejects new identities with 429 rather than evicting active budgets. Restart
resets in-memory budgets, not passwords or JWT validity. The existing failed-login
limit remains 10 attempts per minute per socket peer IP with a bounded table;
successful login resets its failure counter. Forwarded-IP headers are not trusted.
Behind a reverse proxy, login limits therefore group clients by the proxy socket
IP. The global concurrency cap also covers bcrypt login work and invalid tokens.

HTTP admission is not a substitute for an ingress proxy's connection/time limits,
TLS, and network access controls. Existing HTTP server timeouts remain unchanged.
No new networking, routing, firewall, SSH, or deployment behavior is introduced.
