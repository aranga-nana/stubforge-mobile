# StubForge Mobile

<div align="center">
  <img src="docs/assets/stub-forge-mobile.png" alt="StubForge Mobile Logo" width="200" height="200">
</div>

![Mobile Development](https://img.shields.io/badge/Mobile%20Development-Made%20Easy-brightgreen?style=for-the-badge) ![Configurable Stubs](https://img.shields.io/badge/Stubs-Configurable-blue?style=for-the-badge) ![OAuth2 Built-in](https://img.shields.io/badge/OAuth2-Built--in-lightgrey?style=for-the-badge) ![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge) ![PRs Welcome](https://img.shields.io/badge/PRs-welcome-green?style=for-the-badge)

**Configurable stub server with built-in OAuth2 for mobile development.** Forge perfect API responses and OAuth2 flows for your iOS & Android apps in minutes, not days.

## 🚀 Why Mobile Developers Love StubForge

**Stop waiting for backends.** Start building mobile apps immediately with:

- ✅ **Configurable API Stubs** - Create any API response you need
- ✅ **Built-in OAuth2** - Every flow your mobile app needs (PKCE, Device, Implicit, etc.)
- ✅ **Real JWT Tokens** - RS256 signed tokens your app can actually validate
- ✅ **Smart Response Rules** - Dynamic responses based on your request data
- ✅ **Zero Configuration** - Works out of the box, customize when needed
- ✅ **Mobile-First Design** - Built specifically for iOS & Android development workflows
- ✅ **Offline Development** - No internet required, perfect for flights and coffee shops

## 🎯 Perfect For

- **Mobile App Development** - Test authentication flows without backend dependency
- **Prototyping** - Quickly demo mobile apps with realistic auth behavior  
- **Integration Testing** - Validate your OAuth2 implementation against all standard flows
- **Learning OAuth2** - Hands-on experience with real flows and tokens
- **Conference Demos** - Reliable offline demo environment

## 📋 Requirements

- **Node.js** 18+ (LTS recommended)
- **Express.js** 4.18+ (automatically installed)
- **OpenSSL** (for JWT key generation)

## ⚡ Quick Start (60 seconds)

```bash
# 1. Clone and install
git clone https://github.com/aranga-nana/stubforge-mobile.git
cd stubforge-mobile
npm install

# 2. Generate keys (first time only)
mkdir -p keys
openssl genrsa -out keys/private.pem 2048
openssl rsa -in keys/private.pem -pubout -out keys/public.pem

# 3. Start the server
npm run dev
```

**That's it!** Your mobile development server is running at http://localhost:3000

### 🛠️ Core Dependencies

StubForge Mobile is built on these reliable technologies:

- **Express.js** - Fast, unopinionated web framework for Node.js
- **jsonwebtoken** - JWT token creation and validation
- **path-to-regexp** - Flexible URL pattern matching
- **cors** - Cross-Origin Resource Sharing support
- **dotenv** - Environment variable management

## 📱 Mobile Integration Examples

### iOS Swift (Complete PKCE Flow)
```swift
import Foundation
import CryptoKit

// 1. Generate PKCE parameters
let verifier = generateCodeVerifier()
let challenge = Data(SHA256.hash(data: verifier.data(using: .utf8)!))
    .base64URLEncodedString()

// 2. Authorization request
let authURL = URL(string: "http://localhost:3000/oauth/authorize?response_type=code&client_id=mobile-app&redirect_uri=myapp://callback&scope=openid profile&code_challenge=\(challenge)&code_challenge_method=S256")!

// Handle the redirect and extract the code, then:
// 3. Token exchange
exchangeCodeForTokens(code: authCode, verifier: verifier)
```

### Android Kotlin (OkHttp + PKCE)
```kotlin
// Perfect for Android development with emulator support
val baseUrl = "http://10.0.2.2:3000" // Auto-routes to host machine

class OAuth2Helper {
    suspend fun performPKCEFlow(): TokenResponse {
        val verifier = generateCodeVerifier()
        val challenge = verifier.sha256().base64UrlEncode()
        
        // Authorization + Token exchange
        return exchangeCodeForToken(verifier, challenge)
    }
}
```

## 🎮 Interactive Testing with Postman

Import the included Postman collection for **automated OAuth2 flow testing**:

1. **Import**: `postman/OAuth2-Complete-Flows.postman_collection.json`
2. **Set Environment**: `postman/OAuth2-StubKit-Mobile-Local.postman_environment.json`  
3. **Run Any Flow**: Authorization Code, Device Flow, Client Credentials, etc.

**Auto-magic features:**
- ✨ Automatic PKCE code generation and verification
- ✨ Token extraction and validation
- ✨ Flow state management across requests
- ✨ JWT decoding and claims verification

## 🔧 Smart API Stubs

Beyond OAuth2, create realistic API responses for your mobile app:

```javascript
// stubs/users/profile/rule.json
{
  "match": { "method": "GET", "path": "/api/user/profile" },
  "response": { "file": "response.json" }
}

// stubs/users/profile/response.json  
{
  "status": 200,
  "body": {
    "id": "{{query.userId}}",
    "name": "Mobile Developer",
    "avatar": "https://avatar.example.com/{{query.userId}}.jpg",
    "lastLogin": "{{Date.now}}"
  }
}
```

**Dynamic responses** based on query parameters, request body, headers, and more!

## 🎯 All OAuth2 Flows Supported

**Every OAuth2 flow your mobile app might need:**

| Flow | Use Case | Mobile Example |
|------|----------|----------------|
| **Authorization Code + PKCE** | Standard mobile auth | iOS/Android app login |
| **Device Flow** | Smart TV, IoT devices | Apple TV app, Smart display |
| **Client Credentials** | Service-to-service | Background data sync |
| **Implicit Flow** | Legacy web views | Embedded browser auth |
| **JWT Bearer** | Service accounts | Server-side mobile backend |
| **Refresh Token** | Token renewal | Seamless re-authentication |

**Plus OpenID Connect:** ID tokens, UserInfo endpoint, Discovery document - everything for modern mobile authentication.

## ⚙️ Customizable for Your Needs

**All endpoints are configurable** - adapt to match your existing API structure:

```json
{
  "oauth": {
    "basePath": "/auth",           // Change from /oauth to /auth
    "tokenPath": "/auth/token",    // Custom token endpoint
    "userinfoPath": "/auth/me"     // Custom userinfo endpoint
  }
}
```

**Perfect for:**
- Testing against different OAuth2 server configurations
- Matching your production API structure
- Educational purposes and OAuth2 learning

## 🛠️ Advanced Features

- **🔄 Hot Reload** - Modify API responses without restart (`WATCH_RULES=1`)
- **🐳 Docker Ready** - Containerized deployment with auto key generation
- **🔐 Security Testing** - Test different client authentication methods
- **📊 Request Logging** - Debug mobile app requests in real-time
- **⏱️ Response Delays** - Simulate network conditions and timeouts
- **🎭 Multiple Environments** - Different configs for different test scenarios

## 🐳 Docker Deployment

Perfect for CI/CD and team development:

```bash
# Build and run with Docker
docker build -t oauth2-stubkit-mobile .
docker run --rm -p 3000:3000 oauth2-stubkit-mobile

# With persistent keys
docker run --rm -p 3000:3000 -v "$PWD/keys:/app/keys" oauth2-stubkit-mobile
```

## 📚 Technical Details

<details>
<summary><strong>🔑 RSA Key Management</strong></summary>

The server uses RSA keys for JWT signing. Keys are git-ignored for security:

```bash
# Generate keys (first time only)
mkdir -p keys
openssl genrsa -out keys/private.pem 2048
openssl rsa -in keys/private.pem -pubout -out keys/public.pem

# Verify key format
head -n2 keys/private.pem  # Should show: -----BEGIN RSA PRIVATE KEY-----
head -n2 keys/public.pem   # Should show: -----BEGIN PUBLIC KEY-----
```

**Important:** Never commit `.pem` files to git. Only `keys/.gitkeep` is tracked.
</details>

<details>
<summary><strong>🔧 Manual OAuth2 Testing (curl examples)</strong></summary>

### Authorization Code + PKCE Flow
```bash
# 1. Generate PKCE verifier and challenge
code_verifier="YOUR_GENERATED_VERIFIER"
code_challenge=$(echo -n $code_verifier | shasum -a 256 | cut -d' ' -f1 | xxd -r -p | base64 | tr '+/' '-_' | tr -d '=')

# 2. Authorization request (browser)
curl "http://localhost:3000/oauth/authorize?response_type=code&client_id=mobile-app&redirect_uri=http://localhost:3000/callback&scope=openid profile&code_challenge=$code_challenge&code_challenge_method=S256"

# 3. Token exchange (extract code from redirect)
curl -X POST http://localhost:3000/oauth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "grant_type=authorization_code&code=EXTRACTED_CODE&redirect_uri=http://localhost:3000/callback&code_verifier=$code_verifier&client_id=mobile-app"
```

### Other Grant Types
```bash
# Password Grant
curl -X POST http://localhost:3000/oauth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=password&username=alice&password=secret&scope=basic'

# Client Credentials
curl -X POST http://localhost:3000/oauth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials&client_id=svc&scope=service'

# Refresh Token
curl -X POST http://localhost:3000/oauth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=refresh_token&refresh_token=YOUR_REFRESH_JWT'

# Device Flow (step 1)
curl -X POST http://localhost:3000/oauth/device_authorization \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'client_id=device-app&scope=basic'

# Device Flow (step 2 - polling)
curl -X POST http://localhost:3000/oauth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=DEVICE_CODE'
```
</details>

## 🎨 Creating Custom API Stubs

Build realistic API responses for your mobile app testing:

### Basic Stub Structure
```json
// stubs/products/list/rule.json
{
  "id": "products-list",
  "match": { 
    "method": "GET", 
    "path": "/api/products",
    "query": {"category": "electronics"}
  },
  "response": { "file": "response.json", "delayMs": 100 }
}
```

```json
// stubs/products/list/response.json
{
  "status": 200,
  "body": {
    "products": [
      {
        "id": "{{query.category}}-001",
        "name": "Mobile Phone",
        "price": 699,
        "category": "{{query.category}}",
        "lastUpdated": "{{Date.now}}"
      }
    ],
    "total": 1,
    "requestedCategory": "{{query.category}}"
  }
}
```

### Template Variables
**Dynamic content** using template variables:
- `{{query.paramName}}` - URL query parameters
- `{{params.id}}` - Path parameters (e.g., `/users/:id`)  
- `{{body.fieldName}}` - Request body fields
- `{{Date.now}}` - Current timestamp

### Multiple Response Variants
```bash
# Different responses based on query parameters
curl http://localhost:3000/api/products                    # Default response
curl http://localhost:3000/api/products?category=premium   # Premium category response
```

### Request Body Variants
```json
// Match requests containing specific body fields
{
  "match": {
    "method": "POST",
    "path": "/api/orders",
    "bodyContains": ["productId", "quantity"]
  }
}
```

## 🔧 Configuration Options

Edit `config/local.json` to customize:

```json
{
  "port": 3000,
  "logging": true,
  "globalDelayMs": 0,
  "allowDefaultClient": false,  // Security: require explicit client auth
  "cors": {
    "enabled": true,
    "origins": ["*"]
  },
  "oauth": {
    "basePath": "/oauth",
    "authorizePath": "/oauth/authorize",
    "tokenPath": "/oauth/token",
    "devicePath": "/oauth/device_authorization",
    "introspectPath": "/oauth/introspect",
    "revokePath": "/oauth/revoke",
    "userinfoPath": "/oauth/userinfo"
  }
}
```

### Key Configuration Options
- **`allowDefaultClient`** - Set to `true` to allow fallback authentication (not recommended for production-like testing)
- **`globalDelayMs`** - Add artificial delay to all responses (simulate network latency)
- **All OAuth2 endpoints** - Fully customizable paths to match your API structure
- **CORS settings** - Configure for your mobile app's requirements

## 🚀 Quick Mobile Development Tips

### iOS Development
```bash
# Use localhost for iOS Simulator
let baseURL = "http://localhost:3000"

# For device testing, use your machine's IP
let baseURL = "http://192.168.1.100:3000"  // Replace with your IP
```

### Android Development  
```bash
# Android Emulator automatically maps to host
let baseURL = "http://10.0.2.2:3000"

# For device testing, use your machine's IP
let baseURL = "http://192.168.1.100:3000"  // Replace with your IP
```

### Hot Reload for Fast Iteration
```bash
# Start with hot reload enabled
WATCH_RULES=1 npm run dev

# Now modify any file in stubs/ - changes apply instantly!
```

## 🛠️ Troubleshooting

| Issue | Solution |
|-------|----------|
| **404 Not Found** | Check rule matching (path, method, query params) |
| **PKCE invalid_grant** | Verify code_verifier matches code_challenge |
| **JWT signing error** | Regenerate RSA keys (see Technical Details) |
| **CORS errors** | Enable CORS in config or adjust origins |
| **Connection refused** | Check server is running on correct port |

## 🤝 Contributing

We love contributions! This project is perfect for:
- Adding new OAuth2 flows
- Mobile-specific testing scenarios  
- Additional stub rule examples
- Documentation improvements

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

**Made with ❤️ for mobile developers who want to focus on building great apps, not wrestling with authentication infrastructure.**

> **StubForge Mobile** - Forge perfect API responses and OAuth2 flows for mobile development.
