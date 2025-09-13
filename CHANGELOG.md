# Changelog

## Unreleased
*(No unreleased changes yet)*

## 1.5.0 - 2025-09-13
### Added
- New Postman collection `OAuth2-StubKit-Mobile-PKCE` with fully configurable OAuth path variables.
- New Postman environment `OAuth2-StubKit-Mobile-Local` mapping to `config/local.json` paths.
- Cleanup script `clean:postman` and helper `scripts/remove-legacy-postman.js`.

### Changed
- README: Added Postman section referencing variable-driven endpoints.
- `.env.example`: Trimmed to only supported variables.

### Removed
- Legacy Postman assets (`StubServer-OAuth2-PKCE.postman_collection.json`, `StubServer-Local.postman_environment.json`).
- Unused `config/rules` directory.

### Deprecated
- Added minimal JSON stubs in place of removed legacy Postman files (may be deleted in a future major/minor release).

### Internal / Maintenance
- Integrity validation after cleanup (rule validator, server boot check) – no regressions found.

## 1.0.0
- Initial public release: OAuth2 Authorization Code + PKCE (S256), password, client_credentials, refresh grants.
- RS256 JWT signing + JWKS endpoint.
- Config-driven stub rule system (query/body matching, templating, delays).
- Postman PKCE automated flow collection.
- Example product & order rules.
