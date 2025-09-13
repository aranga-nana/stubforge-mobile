# Changelog

## [Unreleased] - v1.2.0-dev (feature/comple-oauth-flow)
### Added - Complete OAuth2 & OpenID Connect Support
- **Device Authorization Grant (RFC 8628)** - Device flow for smart TVs, IoT devices
- **Implicit Flow** - Direct access token response for legacy web apps
- **JWT Bearer Grant (RFC 7523)** - Service-to-service authentication with JWT assertions
- **Token Introspection (RFC 7662)** - Endpoint to validate access tokens
- **Token Revocation (RFC 7009)** - Endpoint to revoke access and refresh tokens
- **OpenID Connect Support** - ID tokens, UserInfo endpoint, and Discovery endpoint
- **Hybrid Flows** - Support for combined response types (code+token, code+id_token, etc.)
- **Enhanced Client Authentication** - client_secret_basic, client_secret_post, private_key_jwt, none
- **Comprehensive Postman Collection** - Organized folders for each OAuth2 flow with automated tests
- **Fully Configurable Endpoints** - All OAuth2 paths customizable in config/local.json

### Enhanced
- Authorization endpoint now supports all OAuth2 response types
- Token endpoint supports all standard grant types
- Improved error handling and validation
- Enhanced documentation with endpoint configuration guide

### Fixed
- Refresh token flow now properly handles client authentication
- PKCE validation improved with better error messages
- JWT token signing with proper claims and validation

### Endpoints Added
- `POST /oauth/device_authorization` - Device flow initiation
- `GET /device` - Device verification page
- `POST /device/verify` - Device verification handler
- `POST /oauth/introspect` - Token introspection
- `POST /oauth/revoke` - Token revocation
- `GET /oauth/userinfo` - OpenID Connect UserInfo
- `GET /.well-known/openid_configuration` - OIDC Discovery

### Configuration
- Added comprehensive endpoint configuration in `config/local.json`
- Created `config/local.example.json` with all configuration options
- All OAuth2 endpoint paths are now user-configurable

## 1.0.0 - 2025-09-13
### Initial Release
- OAuth2 Authorization Code + PKCE (S256), password, client_credentials, refresh grants
- RS256 JWT signing + JWKS endpoint
- Config-driven stub rule system (query/body matching, templating, delays)
- Postman PKCE automated flow collection
- Example product & order rules

## Unreleased
*(No unreleased changes yet)*
