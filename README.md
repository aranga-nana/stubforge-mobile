# oauth2-stubkit-mobile

![PKCE Mobile Ready](https://img.shields.io/badge/Mobile%20OAuth2-PKCE%20Ready-brightgreen?style=for-the-badge) ![JWT](https://img.shields.io/badge/Tokens-JWT%20RS256-blue?style=for-the-badge) ![Stubs](https://img.shields.io/badge/Config-Stub%20Rules-lightgrey?style=for-the-badge) ![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge) ![PRs Welcome](https://img.shields.io/badge/PRs-welcome-green?style=for-the-badge) ![Release](https://img.shields.io/github/v/tag/aranga-nana/oauth2-stubkit-mobile?label=release&style=for-the-badge)

Spin up a local, config-driven OAuth2 Authorization Code (PKCE) + JWT stub API in under 60 seconds for rapid iOS & Android mobile app development. NOT for production; purpose-built for local dev, integration testing, and iterative UI flows.

Key features:
- Authorization Code + PKCE (S256) plus password, client_credentials & refresh grants
- RS256-signed JWT access & refresh tokens with JWKS (`/.well-known/jwks.json`)
- Configurable stub rule folders (method/path/query/body matching, templating, delays)
- Query + body variant examples included (products, orders)
- Hot reload of rules (set `WATCH_RULES=1`)
- Postman collection automates full PKCE flow (auto-captures auth code, integrity checks)
- Safe key handling (git-ignored PEMs; instructions included)
- Docker image & rule validation script
- Minimal dependencies; fast startup

## Demo (GIF)
> Placeholder: Add `docs/media/pkce-flow.gif` showing Postman auto PKCE (Steps 1-3). To record: use screen capture, optimize with `gifski` or `ffmpeg` + `imagemagick`, then commit under `docs/media/` and update path below.

![PKCE Flow Demo](docs/media/pkce-flow.gif)

## Why
Standing up a full identity provider + backend just to iterate on mobile auth UX is slow. This project gives you:
- Realistic OAuth2 Authorization Code + PKCE exchange (S256)
- Signed JWTs you can decode & validate in app (public key / JWKS provided)
- Dynamic mock API responses selected by rules (query/body driven) for rapid state simulation
- Simple folder-based rules you can version with your app
- No external services required; works fully offline

## Quick Start
```
# Install & run
npm install
npm run dev
# or with Docker (auto key gen if absent)
docker build -t oauth2-stubkit-mobile .
docker run --rm -p 3000:3000 -v "$PWD/keys:/app/keys" oauth2-stubkit-mobile
```
Server: http://localhost:3000
Health: http://localhost:3000/health
JWKS: http://localhost:3000/.well-known/jwks.json

## iOS Swift (Authorization Code Exchange Example)
```swift
let base = URL(string: "http://localhost:3000")!
let codeVerifier = "<your generated verifier>"
let codeChallenge = /* BASE64URL(SHA256(verifier)) */
let authorize = URL(string: "/oauth/authorize?response_type=code&client_id=mobile-app&redirect_uri=http://localhost:3000/callback&scope=openid%20profile&state=abc123&code_challenge=\(codeChallenge)&code_challenge_method=S256", relativeTo: base)!
URLSession.shared.dataTask(with: authorize) { _, resp, _ in
    if let http = resp as? HTTPURLResponse, let loc = http.value(forHTTPHeaderField: "Location") {
        let code = URLComponents(string: loc)?.queryItems?.first { $0.name == "code" }?.value ?? ""
        var req = URLRequest(url: base.appendingPathComponent("/oauth/token"))
        req.httpMethod = "POST"
        req.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        let body = "grant_type=authorization_code&code=\(code)&redirect_uri=http://localhost:3000/callback&code_verifier=\(codeVerifier)&client_id=mobile-app"
        req.httpBody = body.data(using: .utf8)
        URLSession.shared.dataTask(with: req) { data, _, _ in
            if let d = data { print(String(data: d, encoding: .utf8)!) }
        }.resume()
    }
}.resume()
```

## Android Kotlin (OkHttp)
```kotlin
val client = OkHttpClient()
val base = "http://10.0.2.2:3000" // Android emulator -> host
val verifier = "<generated>"
val challenge = /* base64url(sha256(verifier)) */
val authUrl = HttpUrl.parse("$base/oauth/authorize")!!.newBuilder()
    .addQueryParameter("response_type","code")
    .addQueryParameter("client_id","mobile-app")
    .addQueryParameter("redirect_uri","http://localhost:3000/callback")
    .addQueryParameter("scope","openid profile")
    .addQueryParameter("state","abc123")
    .addQueryParameter("code_challenge", challenge)
    .addQueryParameter("code_challenge_method","S256")
    .build()
val authReq = Request.Builder().url(authUrl).build()
client.newCall(authReq).execute().use { resp ->
    val location = resp.header("Location") ?: return@use
    val code = HttpUrl.parse(location)!!.queryParameter("code") ?: return@use
    val form = FormBody.Builder()
        .add("grant_type","authorization_code")
        .add("code", code)
        .add("redirect_uri","http://localhost:3000/callback")
        .add("code_verifier", verifier)
        .add("client_id","mobile-app")
        .build()
    val tokenReq = Request.Builder().url("$base/oauth/token").post(form).build()
    client.newCall(tokenReq).execute().use { tokenResp ->
        println(tokenResp.body()!!.string())
    }
}
```

## OAuth2 PKCE Flow (S256)
1. Generate `code_verifier` (43–128 chars allowed: A-Z a-z 0-9 -._~).
2. Compute `code_challenge = BASE64URL(SHA256(code_verifier))`.
3. Authorize:
```
GET /oauth/authorize?response_type=code&client_id=mobile-app&redirect_uri=http://localhost:3000/callback&scope=openid%20profile&state=abc123&code_challenge=...&code_challenge_method=S256
```
4. Copy `code` from redirect URL.
5. Token exchange:
```
curl -X POST http://localhost:3000/oauth/token \
 -H 'Content-Type: application/x-www-form-urlencoded' \
 -d 'grant_type=authorization_code&code=CODE&redirect_uri=http://localhost:3000/callback&code_verifier=ORIGINAL_VERIFIER&client_id=mobile-app'
```
Returns `access_token` + `refresh_token` (JWT, RS256). JWKS: `/.well-known/jwks.json`.

## RSA Keys (Do Not Commit)
Directory `keys/` is tracked but key files are git‑ignored. Create locally:
```
mkdir -p keys
openssl genrsa -out keys/private.pem 2048
openssl rsa -in keys/private.pem -pubout -out keys/public.pem
```
Verify headers:
```
head -n2 keys/private.pem
head -n2 keys/public.pem
```
If you rotate keys, just regenerate both. Never commit the actual `.pem` files; only `keys/.gitkeep` stays in Git.

## Other Grants
Password:
```
curl -X POST http://localhost:3000/oauth/token -H 'Content-Type: application/x-www-form-urlencoded' -d 'grant_type=password&username=alice&password=secret&scope=basic'
```
Client Credentials:
```
curl -X POST http://localhost:3000/oauth/token -H 'Content-Type: application/x-www-form-urlencoded' -d 'grant_type=client_credentials&client_id=svc&scope=service'
```
Refresh:
```
curl -X POST http://localhost:3000/oauth/token -H 'Content-Type: application/x-www-form-urlencoded' -d 'grant_type=refresh_token&refresh_token=REFRESH_JWT'
```

## Templated Stub Rules
Rules live under `stubs/` and auto-load. Each rule file: `rule*.json` with:
```
{
  "id": "unique-id",
  "match": { "method": "GET", "path": "/products", "query": {"category":"premium"}, "bodyContains": ["field"] },
  "response": { "file": "response.file.json", "delayMs": 0 }
}
```
Response file:
```
{
  "status": 200,
  "body": { "value": "{{query.category}}", "id": "{{params.id}}", "input": "{{body.productId}}", "ts": "{{Date.now}}" }
}
```
Supported template sources: `params.*`, `query.*`, `body.*`, `Date.now`.

## Query Param Variant Example
Default list:
- `stubs/products/list/rule.products.json` -> `/products`
Filtered list when `?category=premium`:
- `stubs/products/list-filtered/rule.products.filtered.json`

Test:
```
curl http://localhost:3000/products
curl http://localhost:3000/products?category=premium
```

## Request Body Variant Example
Order create success:
- `stubs/orders/create/rule.orders.create.json` (body contains `productId`)
Order create missing product:
- `stubs/orders/create/rule.orders.create.missing.json` (only sees `quantity`)

Test:
```
curl -X POST http://localhost:3000/orders -H 'Content-Type: application/json' -d '{"productId":"p1","quantity":2}'
curl -X POST http://localhost:3000/orders -H 'Content-Type: application/json' -d '{"quantity":2}'
```

## Add New Endpoint
1. Create folder under `stubs/...`.
2. Add `rule.something.json` with match criteria.
3. Add `response.something.json` with `status` + `body`.
4. Restart or run with `WATCH_RULES=1` for auto reload.

## Troubleshooting
- 404: No rule matched (check path/method)
- PKCE invalid_grant: mismatch verifier vs challenge or reused code
- JWT signing error: regenerate keys (see RSA Keys)

## Config
Edit `config/local.json` for port, CORS, global delay, fallback.

## Configurable OAuth2 Endpoints
All OAuth2 and OpenID Connect endpoints are fully configurable in `config/local.json`. This allows you to match your existing API structure or test different endpoint configurations:

```json
{
  "oauth": {
    "basePath": "/oauth",
    "authorizePath": "/oauth/authorize",
    "tokenPath": "/oauth/token", 
    "devicePath": "/oauth/device_authorization",
    "introspectPath": "/oauth/introspect",
    "revokePath": "/oauth/revoke",
    "userinfoPath": "/oauth/userinfo",
    "jwksPath": "/.well-known/jwks.json",
    "publicKeyPath": "/.well-known/public.pem",
    "discoveryPath": "/.well-known/openid_configuration",
    "deviceVerificationPath": "/device",
    "deviceVerifyPath": "/device/verify"
  }
}
```

### Available Endpoints
| Endpoint | Purpose | Configurable Path |
|----------|---------|-------------------|
| Authorization | OAuth2 authorization endpoint | `authorizePath` |
| Token | Token exchange endpoint | `tokenPath` |
| Device Authorization | Device flow initiation | `devicePath` |
| Token Introspection | Validate tokens | `introspectPath` |
| Token Revocation | Revoke tokens | `revokePath` |
| UserInfo | OpenID Connect user info | `userinfoPath` |
| Discovery | OpenID Connect discovery | `discoveryPath` |
| JWKS | JSON Web Key Set | `jwksPath` |
| Public Key | RSA public key | `publicKeyPath` |
| Device Verification | Device code verification page | `deviceVerificationPath` |
| Device Verify | Device code form handler | `deviceVerifyPath` |

### Example Custom Configuration
```json
{
  "oauth": {
    "basePath": "/auth",
    "authorizePath": "/auth/authorize",
    "tokenPath": "/auth/token",
    "userinfoPath": "/auth/me",
    "jwksPath": "/auth/jwks",
    "discoveryPath": "/auth/.well-known/openid_configuration"
  }
}
```

### Supported OAuth2 Flows
- ✅ **Authorization Code Flow** (with PKCE S256/plain)
- ✅ **Implicit Flow** (response_type=token)
- ✅ **Resource Owner Password Credentials Flow**
- ✅ **Client Credentials Flow** 
- ✅ **Refresh Token Flow**
- ✅ **Device Authorization Grant** (RFC 8628)
- ✅ **JWT Bearer Grant** (RFC 7523)
- ✅ **OpenID Connect** (ID tokens, UserInfo, Discovery)

### Client Authentication Methods
- ✅ **client_secret_basic** (Authorization header)
- ✅ **client_secret_post** (form parameters)  
- ✅ **private_key_jwt** (JWT assertion)
- ✅ **none** (public clients)

## Docker
```
docker build -t oauth2-stubkit-mobile .
docker run --rm -p 3000:3000 oauth2-stubkit-mobile
```
Mount keys to persist / reuse:
```
docker run --rm -p 3000:3000 -v $PWD/keys:/app/keys oauth2-stubkit-mobile
```
Generate & inspect a token quickly:
```
TOKEN=$(curl -s -X POST http://localhost:3000/oauth/token -H 'Content-Type: application/x-www-form-urlencoded' -d 'grant_type=client_credentials&client_id=svc&scope=basic' | jq -r .access_token)
printf '%s\n' "$TOKEN" | cut -d'.' -f2 | base64 -D 2>/dev/null | jq
```
(Use `base64 -d` on Linux.)

## Validate Rules
```
npm run validate:rules
```
Ensures every `rule*.json` has id, match + response.file exists.

## Postman Collections
Updated PKCE collection & environment live in `postman/`:
- Collection: `OAuth2-StubKit-Mobile-PKCE.postman_collection.json`
- Environment: `OAuth2-StubKit-Mobile-Local.postman_environment.json`

Environment variables map directly to values in `config/local.json` so you can change OAuth paths without editing the requests:
- `base_url` -> `http://localhost:3000`
- `oauth_authorize_path` -> `oauth.authorizePath`
- `oauth_token_path` -> `oauth.tokenPath`
- `oauth_jwks_path` -> `oauth.jwksPath`
- `oauth_public_key_path` -> `oauth.publicKeyPath`

Run flow steps in order (Reset -> Step 1 -> Step 2 -> Step 3 -> Step 5 -> Step 4 as needed). Auto-capture of `auth_code` via Location header is built in.

## Contributing
See `CONTRIBUTING.md` & `CODE_OF_CONDUCT.md`. PRs welcome.

## Roadmap
- Optional JWT auth middleware for protected stubs
- Auth code expiry & cleanup job
- Advanced templating helpers
- OpenAPI generation from rules

## Star & Share
If this saved you time, please ⭐ the repo & share.

## License
MIT
