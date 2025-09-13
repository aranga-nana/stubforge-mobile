# Postman Collections

This folder contains comprehensive Postman collections for testing all OAuth2 and OpenID Connect flows supported by the stub server.

## Collections Available

### 1. OAuth2-StubKit-Complete-Flows (RECOMMENDED)
**File:** `OAuth2-StubKit-Complete-Flows.postman_collection.json`
**Environment:** `OAuth2-StubKit-Complete-Environment.postman_environment.json`

This is the comprehensive collection that includes all OAuth2 flows organized in logical folders:

#### 📁 **Folder Structure:**
- **🏠 Setup & Health** - Server health check, discovery, and JWKS endpoints
- **🔐 Authorization Code Flow (PKCE)** - Complete PKCE flow with automatic code capture
- **🌐 Implicit Flow** - Direct access token retrieval for web apps
- **🔑 Client Credentials Flow** - Service-to-service authentication
- **👤 Resource Owner Password Flow** - Username/password authentication
- **🔄 Refresh Token Flow** - Token refresh using refresh tokens
- **📱 Device Code Flow** - Smart TV/IoT device authentication
- **🔐 JWT Bearer Flow** - JWT assertion-based authentication
- **🔍 Token Management** - Token introspection and revocation
- **🆔 OpenID Connect** - ID tokens, UserInfo, and hybrid flows
- **🧪 API Testing** - Protected resource examples

### 2. OAuth2-StubKit-Mobile-PKCE (LEGACY)
**File:** `OAuth2-StubKit-Mobile-PKCE.postman_collection.json`
**Environment:** `OAuth2-StubKit-Mobile-Local.postman_environment.json`

Legacy collection focused only on Authorization Code + PKCE flow. Use the complete collection above instead.

## Quick Start

1. **Start the server:**
   ```bash
   npm run dev
   # Server runs on http://localhost:3000
   ```

2. **Import into Postman:**
   - Import `OAuth2-StubKit-Complete-Flows.postman_collection.json`
   - Import `OAuth2-StubKit-Complete-Environment.postman_environment.json`
   - Select the imported environment

3. **Test different flows:**
   - Each folder contains a complete flow for that OAuth2 grant type
   - Run requests in order within each folder
   - Variables are automatically captured and reused

## Flow Testing Guide

### 🔐 Authorization Code Flow (PKCE)
**Use Case:** Mobile apps, SPAs with secure backend
1. **Reset PKCE Variables** - Clear previous session
2. **Step 1 - Generate PKCE Challenge** - Creates verifier and challenge
3. **Step 2 - Authorization Request** - Auto-captures authorization code
4. **Step 3 - Token Exchange** - Exchanges code for tokens

### 📱 Device Code Flow  
**Use Case:** Smart TVs, IoT devices, limited input devices
1. **Step 1 - Device Authorization Request** - Get device and user codes
2. **Manual Step:** Visit the verification URI and enter the user code
3. **Step 2 - Poll for Token** - Exchange device code for tokens (wait 10 seconds after manual step)

### 🌐 Implicit Flow
**Use Case:** Legacy web applications
1. **Implicit Grant Request** - Directly receive access token via URL fragment

### 🔑 Client Credentials Flow
**Use Case:** Service-to-service authentication
1. **Client Credentials Grant** - Exchange client credentials for access token

### 👤 Resource Owner Password Flow
**Use Case:** Trusted applications (not recommended for production)
1. **Password Grant** - Exchange username/password for tokens

### 🔄 Refresh Token Flow
**Use Case:** Renewing expired access tokens
1. **Refresh Token Grant** - Exchange refresh token for new tokens
   - Requires `refresh_token` from a previous flow

### 🔐 JWT Bearer Flow
**Use Case:** Service-to-service with JWT assertions
1. **JWT Bearer Grant** - Exchange JWT assertion for access token

### 🔍 Token Management
**Use Case:** Token validation and cleanup
1. **Token Introspection** - Validate and inspect token details
2. **Token Revocation** - Revoke access or refresh tokens

### 🆔 OpenID Connect
**Use Case:** Identity and authentication
1. **UserInfo Endpoint** - Get user information with access token
2. **OpenID Connect with ID Token** - Direct ID token via implicit flow
3. **Hybrid Flow** - Combination of authorization code and ID token

## Environment Variables

The environment includes all necessary variables that are automatically populated by the collection scripts:

### Base Configuration
- `base_url` - Server URL (default: http://localhost:3000)
- `client_id`, `client_secret` - Client credentials
- `redirect_uri` - OAuth redirect URI
- `scope` - OAuth scopes

### Flow-Specific Variables
- PKCE: `code_verifier`, `code_challenge`, `auth_code`
- Tokens: `access_token`, `refresh_token`, `id_token`
- Device Flow: `device_code`, `user_code`, `verification_uri`
- And many more...

## Configurable Endpoints

The collection uses the `base_url` variable and builds endpoint URLs dynamically. If you change OAuth paths in `config/local.json`, just update the `base_url` variable - no need to edit individual requests.

## Tips for Testing

1. **Run flows in order** - Each folder's requests should be run sequentially
2. **Check the Console** - Important information is logged to Postman console
3. **Use different client IDs** - Each flow uses appropriate client IDs (mobile-app, tv-app, etc.)
4. **Environment variables persist** - Tokens are automatically captured and available for subsequent requests
5. **Test protected APIs** - Use the "API Testing" folder to test your access tokens

## Troubleshooting

- **404 errors:** Check that the server is running on the correct port
- **PKCE failures:** Run "Reset PKCE Variables" and start the flow fresh
- **Device flow:** Wait at least 10 seconds after authorizing the device before polling
- **Token validation:** Use Token Introspection to verify token details

Happy testing! 🚀
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

