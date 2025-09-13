# Changelog

All notable changes to **StubForge Mobile** will be documented in this file.

## [1.2.0] - 2025-09-13 - StubForge Mobile Complete
### Added - Complete OAuth2 & OpenID Connect Support
- **Project Rebranding** - Complete transformation to "StubForge Mobile" with mobile-first messaging
- **Visual Identity** - Professional logo integration with branded startup experience
- **ASCII Art Startup Banner** - Prominent "STUBFORGE MOBILE" branding displayed on server startup
- **Complete OAuth2 Implementation** - All 8 standard OAuth2 flows now supported:
  - Authorization Code Flow (with PKCE)
  - Device Authorization Grant (RFC 8628)
  - Implicit Flow
  - Resource Owner Password Credentials Flow
  - Client Credentials Flow
  - Refresh Token Flow
  - JWT Bearer Grant (RFC 7523)
  - Token Introspection & Revocation (RFC 7662, RFC 7009)
- **OpenID Connect Support** - Full OIDC implementation with ID tokens, UserInfo, and Discovery
- **Enhanced Client Authentication** - client_secret_basic, client_secret_post, private_key_jwt, none
- **Mobile-First Documentation** - Comprehensive README with iOS Swift and Android Kotlin examples
- **Professional Postman Collections** - Complete OAuth2 flow testing with automated PKCE generation
- **Fully Configurable Endpoints** - All OAuth2 paths customizable in config/local.json
- **Docker Support** - Containerized deployment with automatic key generation
- **Express.js Integration** - Built on reliable Express.js framework with modern dependencies

### Enhanced
- **Startup Experience** - Rich console output showing all available endpoints and capabilities
- **Security-First Approach** - Configurable client authentication with security warnings
- **Documentation Quality** - Mobile development examples, troubleshooting guides, and technical details
- **Error Handling** - Comprehensive OAuth2 error responses with proper status codes
- **JWT Implementation** - RS256 signing with proper at_hash calculation and token validation
- **Mobile Development Focus** - iOS Simulator and Android Emulator specific networking guidance

### Fixed
- **Refresh Token Authentication** - Proper client authentication handling for refresh flows
- **PKCE Validation** - Improved code verifier validation with detailed error messages
- **JWT at_hash Calculation** - Correct base64url encoding for OpenID Connect compliance
- **Client Authentication Security** - Secure fallback handling with configurable default client support

### Endpoints Added
- `POST /oauth/device_authorization` - Device flow initiation with user codes
- `GET /device/verification` - Styled device verification page
- `POST /device/verify` - Device verification handler with user experience
- `POST /oauth/introspect` - RFC 7662 compliant token introspection
- `POST /oauth/revoke` - RFC 7009 compliant token revocation
- `GET /oauth/userinfo` - OpenID Connect UserInfo endpoint
- `GET /.well-known/openid_configuration` - OIDC Discovery document
- `GET /.well-known/jwks.json` - JSON Web Key Set for token verification
- `GET /.well-known/public.pem` - Public key endpoint for JWT validation

### Configuration
- **Complete Endpoint Configuration** - All OAuth2 paths customizable in `config/local.json`
- **Security Options** - `allowDefaultClient` setting for production-like testing
- **Mobile Development Settings** - CORS configuration for mobile app requirements
- **Performance Options** - Global delay settings for network simulation

### Documentation
- **Mobile Integration Examples** - Complete iOS Swift and Android Kotlin code samples
- **Postman Testing Guide** - Step-by-step OAuth2 flow testing instructions
- **Technical Details** - RSA key management, manual testing with curl examples
- **Troubleshooting Guide** - Common issues and solutions for mobile developers
- **Contributing Guidelines** - Clear instructions for community contributions

### Dependencies
- **Express.js 4.18+** - Fast, unopinionated web framework
- **jsonwebtoken 9.0+** - JWT creation and validation
- **path-to-regexp 6.2+** - Flexible URL pattern matching
- **cors 2.8+** - Cross-Origin Resource Sharing support
- **dotenv 16.4+** - Environment variable management

## [1.0.0] - 2025-09-13
### Initial Release
- OAuth2 Authorization Code + PKCE (S256), password, client_credentials, refresh grants
- RS256 JWT signing + JWKS endpoint
- Config-driven stub rule system (query/body matching, templating, delays)
- Postman PKCE automated flow collection
- Example product & order rules

## Unreleased
*(No unreleased changes yet)*
