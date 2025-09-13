# Postman Assets

This folder contains:
- `OAuth2-StubKit-Mobile-PKCE.postman_collection.json` – Requests for OAuth2 Authorization Code + PKCE flow (auto code capture) using configurable OAuth paths.
- `OAuth2-StubKit-Mobile-Local.postman_environment.json` – Environment variables for base URL and individual OAuth endpoint paths.

## Configurable OAuth Paths
The collection builds URLs dynamically:
- Base URL: `{{base_url}}`
- Authorize: `{{base_url}}{{oauth_authorize_path}}`
- Token: `{{base_url}}{{oauth_token_path}}`
- JWKS: `{{base_url}}{{oauth_jwks_path}}`
- Public Key: `{{base_url}}{{oauth_public_key_path}}`

Adjust these environment values to match `config/local.json` if you change OAuth paths there. No request edits required.

## PKCE Flow (Auto Capture)
Run requests strictly in this order:
1. Reset Flow – Clears all PKCE/session vars.
2. Step 1 - Generate PKCE Verifier & Challenge – Creates (or reuses) RFC7636 compliant `code_verifier`, derives `code_challenge` (S256), sets `state` & session id.
3. Step 2 - Authorize (Auto-capture Code) – Sends authorize request (redirects disabled); test script reads `Location` header, extracts `code` + `state`, stores `auth_code`, and confirms state integrity.
4. Step 3 - Exchange Code for Tokens – Posts `grant_type=authorization_code`; stores `access_token` and `refresh_token`.
5. Step 5 - Call Protected Stub (Example) – Demonstrates using the access token.
6. Step 4 - Refresh Token – (Anytime) exchanges `refresh_token` for new tokens.

Use the manual "Set Auth Code" only if auto-capture fails.

## Quick Start
1. Start server: `npm run dev` (default http://localhost:3000).
2. Import the collection & environment; select the environment.
3. Optional: Run Reset Flow.
4. Run Step 1.
5. Run Step 2 (Location header parsed automatically).
6. Run Step 3 to obtain tokens.
7. Use Step 5 or your own requests with `{{access_token}}`.
8. Use Step 4 to refresh when needed.

## Key Environment Variables
| Key | Purpose |
| --- | --- |
| base_url | API / OAuth base (e.g. http://localhost:3000) |
| oauth_authorize_path | Relative authorize path (matches config) |
| oauth_token_path | Relative token path (matches config) |
| oauth_jwks_path | JWKS path (matches config) |
| oauth_public_key_path | Public key path (matches config) |
| redirect_path | Local redirect path used for forming `redirect_uri` |
| client_id | Public client identifier |
| scope | Space-delimited scopes |
| code_challenge_method | Always S256 here |
| state / returned_state | CSRF state tracking |
| code_verifier / code_challenge | PKCE pair |
| auth_code | Captured authorization code |
| access_token / refresh_token | Issued tokens |
| pkce_session_id / pkce_session_id_confirm | Continuity assertions |

Ephemeral helper: `force_reset`.

## Flow Summary (S256 PKCE)
1. Generate high-entropy `code_verifier`.
2. Derive `code_challenge = BASE64URL(SHA256(verifier))`.
3. Call authorize with challenge + method.
4. Exchange code + verifier at token endpoint.
5. Receive JWT access & refresh tokens.

## Resetting
Run Reset Flow if state mismatch, PKCE failure, or code reuse.

## Troubleshooting
| Symptom | Likely Cause | Fix |
| --- | --- | --- |
| invalid_grant PKCE mismatch | Verifier changed | Reset Flow then redo steps |
| No auth_code after Step 2 | Redirect followed | Ensure followRedirects=false |
| State mismatch | Stale env values | Reset Flow |
| Code invalid | Reused / expired | Re-authorize |
| Access token expired | Normal TTL | Refresh token |

## Notes
- All OAuth endpoints are driven by environment variables reflecting `config/local.json`.
- Changing config paths requires only updating environment values.
- PKCE verifier retained between steps unless Reset Flow is called.

