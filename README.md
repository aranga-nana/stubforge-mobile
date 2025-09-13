# oauth2-stubkit-mobile

![PKCE Mobile Ready](https://img.shields.io/badge/Mobile%20OAuth2-PKCE%20Ready-brightgreen?style=for-the-badge) ![JWT](https://img.shields.io/badge/Tokens-JWT%20RS256-blue?style=for-the-badge) ![Stubs](https://img.shields.io/badge/Config-Stub%20Rules-lightgrey?style=for-the-badge)

Spin up a local, config-driven OAuth2 Authorization Code (PKCE) + JWT stub API in under 60 seconds for rapid iOS & Android mobile app development. NOT for production; purpose-built for local dev, integration testing, and iterative UI flows.

Key features:
- Authorization Code + PKCE (S256) plus password, client_credentials & refresh grants
- RS256-signed JWT access & refresh tokens with JWKS (`/.well-known/jwks.json`)
- Configurable stub rule folders (method/path/query/body matching, templating, delays)
- Query + body variant examples included (products, orders)
- Hot reload of rules (set `WATCH_RULES=1`)
- Postman collection automates full PKCE flow (auto-captures auth code, integrity checks)
- Safe key handling (git-ignored PEMs; instructions included)
- Minimal dependencies; fast startup

## Mobile OAuth2 Stub Server (PKCE) for iOS / Android App Development

Purpose: Fast local HTTP stub + OAuth2 (Authorization Code + PKCE, password, client_credentials, refresh) with signed JWTs.

## Run
```
npm install
npm run dev
```
Server: http://localhost:3000

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

That's it. Keep only what you need.
