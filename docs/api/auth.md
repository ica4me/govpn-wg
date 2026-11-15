# API — Authentication and password changes

Base path: `/api/v1`. Use HTTPS at the reverse proxy; keep the API loopback-bound by default.

## `POST /auth/login`

Public. Existing request/response fields are unchanged.

| Field | Type | Required | Default | Rule |
|---|---|---|---|---|
| `username` | string | yes | none | configured admin account |
| `password` | string | yes | none | current password |

Successful login returns `access_token`, `token_type`, and `expires_at` as before.

Fresh installer defaults to **admin / admin** only when no password hash exists and no password was supplied. Existing installer hashes and API-changed passwords are preserved. The installer and service warn when the bootstrap password is active. Change it immediately; do not expose an unconfigured instance publicly.

## `POST /auth/password`

Requires `Authorization: Bearer <token>` **and** the current password. Strict single JSON object; unknown fields are rejected.

| Field | Type | Required | Default | Rule |
|---|---|---|---|---|
| `current_password` | string | yes | none | must match current admin password |
| `new_password` | string | yes | none | 8–72 bytes (bcrypt limit); bootstrap default is not allowed |

Responses verified by automated HTTP/auth tests:

- `204 No Content`: saved; **all previous tokens are revoked**, including the caller's token. UI must discard its token and return to login.
- `400`: malformed JSON, unknown fields, null/non-object or trailing JSON.
- `401`: missing/invalid bearer token or incorrect current password.
- `422`: invalid new password.
- `429`: too many attempts from the remote IP.
- `500`: unable to persist; current password remains active.
- `503`: password persistence not configured (embedded/test Auth instances).

Errors retain the existing JSON shape: `{"error":"..."}`. Never log request bodies or tokens.

The service persists the bcrypt hash in `GOVPN_DATA_DIR/admin-password.hash` (0600, atomic rename). This override takes precedence over `GOVPN_ADMIN_PASSWORD_HASH` across restarts/reinstalls. To reset administratively: stop the service, securely update the env-file hash using `govpn-wg hash-password`, remove the override, then restart. Removing the override alone reactivates the original installer password; do not do this casually.

Tokens now carry a password-version claim. Tokens issued before this upgrade require login again. No other existing endpoint or JSON response changes.
