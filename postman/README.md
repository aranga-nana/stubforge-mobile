# Postman Assets

This folder contains:
- `StubServer-OAuth2-PKCE.postman_collection.json` – Requests for OAuth2 Authorization Code + PKCE flow (auto code capture) and token usage.
- `StubServer-Local.postman_environment.json` – Environment variables required by the collection.

## Updated PKCE Flow (Auto Capture)
Run requests strictly in this order:
1. Reset Flow (optional at start) – Clears all PKCE/session vars ensuring a clean state.
2. Step 1 - Generate PKCE Verifier & Challenge – Creates (or reuses) RFC7636 compliant `code_verifier`, derives `code_challenge` (S256), sets `state` & session id.
3. Step 2 - Authorize (Auto-capture Code) – Sends `/oauth/authorize` with redirects disabled; test script reads `Location` header, extracts `code` + `state`, stores `auth_code`, and confirms state integrity.
4. Step 3 - Exchange Code for Tokens – Posts `grant_type=authorization_code` including original `code_verifier`; stores `access_token` and `refresh_token`.
5. Step 5 - Call Protected Stub (Example) – Demonstrates using the access token (server does not currently enforce auth on user route).
6. Step 4 - Refresh Token – (Anytime) exchanges `refresh_token` for new tokens.

Only use the manual "Set Auth Code" request if auto-capture fails (rare).

## Quick Start
1. Start server: `npm run dev` (listens on http://localhost:3000).
2. Import the collection and environment; select the environment.
3. (Optional) Run **Reset Flow**.
4. Run **Step 1**.
5. Run **Step 2** (no browser/manual copy needed). Ensure `auth_code` appears in environment.
6. Run **Step 3** to obtain tokens.
7. Use **Step 5** or perform other API calls with `{{access_token}}`.
8. Use **Step 4** to refresh when needed.

## Environment Variables
| Key | Purpose |
| --- | --- |
| base_url | API/stub base (`http://localhost:3000`) |
| auth_base_url | Authorization server base (same) |
| token_url | Token endpoint URL |
| client_id | Public client identifier (e.g. `mobile-app`) |
| redirect_uri | Registered redirect (not actually invoked; code harvested from Location) |
| scope | Space-delimited scopes |
| code_challenge_method | Always `S256` here |
| state | Original state (CSRF) |
| returned_state | State returned from authorize (for integrity check) |
| code_verifier | PKCE verifier (stable until reset) |
| code_challenge | Derived S256 challenge |
| auth_code | Captured authorization code |
| access_token | JWT access token |
| refresh_token | JWT refresh token |
| pkce_session_id | Session marker created at Step 1 |
| pkce_session_id_confirm | Set after Step 2 to assert continuity |
| jwks_url | JWKS endpoint for signature validation |

Ephemeral/internal (may appear): `force_reset` (flag to regenerate on next Step 1).

## Flow Summary (S256 PKCE)
1. Client generates high-entropy `code_verifier` (allowed chars A-Z a-z 0-9 -._~).  
2. Derives `code_challenge = BASE64URL(SHA256(verifier))`.  
3. Calls `/oauth/authorize` with challenge + method=S256. Server stores challenge & method, issues code in redirect.  
4. Client posts `code` + original `code_verifier` to `/oauth/token`. Server recomputes S256 and compares.  
5. On success returns JWT access & refresh tokens.

## Resetting the Flow
Run **Reset Flow** to clear everything, then start at **Step 1**. Do this if:
- State mismatch
- PKCE verification failed
- Code reused / expired

## Troubleshooting
| Symptom | Likely Cause | Fix |
| --- | --- | --- |
| invalid_grant PKCE verification failed | Verifier changed or challenge mismatch | Run Reset Flow, then Steps 1–3 again without re-running Step 1 in between Steps 2 & 3 |
| No auth_code after Step 2 | Redirect followed (should be disabled) or Location missing | Ensure collection kept `followRedirects=false`; rerun Step 2 |
| State mismatch test failure | Environment stale values | Reset Flow and retry |
| Code invalid or expired | Code reused (one-time) or waited too long (server may later add expiry) | Re-run Step 2 |
| Access token expired | Normal TTL | Use Refresh Token (Step 4) |

Check server console for lines like `PKCE S256 mismatch` to compare `computed` vs `expected` if failure persists.

## Optional Improvements
- Add `/callback` endpoint to simulate full redirect chain.
- Enforce client & redirect URI whitelist in server.
- Add auth middleware to protect resource routes with JWT verification.
- Implement auth code expiry & cleanup.

## Notes
- Collection auto-generates compliant verifier (length 64, adjustable) and always re-derives challenge from the stored verifier (no hex conversion errors).
- Do not manually edit `code_challenge`; it is derived each time.
- Avoid running Step 1 again between Steps 2 and 3 unless you also redo Step 2 (new verifier would invalidate code).

