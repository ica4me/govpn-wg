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

The service persists the bcrypt hash in `GOVPN_DATA_DIR/admin-password.hash` (0600, atomic rename). This override takes precedence over `GOVPN_ADMIN_PASSWORD_HASH` across restarts and reinstalls.

Tokens now carry a password-version claim. Tokens issued before this upgrade require login again. No other existing endpoint or JSON response changes.

## `POST /auth/credentials`

Changes the single admin's **username, password, or both**. Requires `Authorization: Bearer <token>` and the current password. Strict JSON; unknown fields are rejected.

| Field | Type | Required | Rule |
|---|---|---|---|
| `current_password` | string | yes | must match the current password |
| `new_username` | string | no | 1–64 characters `A-Z a-z 0-9 _ . @ -`; blank or omitted keeps the current username |
| `new_password` | string | no | 8–72 bytes; not `admin`. Omit to keep the current password. **Required** while the bootstrap password is active |

At least one value must change.

- `200 {"username":"<new>","relogin_required":true}`: saved. **Every existing token is revoked**, including the caller's. Sign in again with the new credentials.
- `401`: bad token or wrong current password. `422`: invalid value or nothing to change. `429`: too many attempts. `500`/`503`: not persisted; the old login stays active.

The username is stored in `GOVPN_DATA_DIR/admin-user` (0600, atomic). It takes precedence over `GOVPN_ADMIN_USER`.

```bash
curl -s -X POST $API/auth/credentials -H "$AUTH" \
  -d '{"current_password":"old-secret","new_username":"boss","new_password":"new-secret-123"}'
```

## `GET /auth/me`

Returns `{"username":"admin","requires_password_change":false}`. Also allowed for a bootstrap token.

## Forgot the login: `govpn-wg reset-admin`

Run on the backend server:

```bash
sudo /opt/govpn/wg/govpn-wg reset-admin
sudo systemctl restart govpn-wg
```

This rewrites `admin-user` and `admin-password.hash` back to **admin / admin**. Tunnels, sites, and clients are not touched. The next login receives `requires_password_change: true`. Every management call returns `403` until a new password is set through `/auth/password` or `/auth/credentials`.
