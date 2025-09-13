// Refactored configurable local-only stub server
const express = require('express');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const { pathToRegexp, match } = require('path-to-regexp');
const jwt = require('jsonwebtoken');
require('dotenv').config();

// Load single local config
const CONFIG_FILE = process.env.CONFIG || path.join(__dirname, 'config', 'local.json');
const config = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));

// New: derive OAuth path configuration
function joinPath(base, segment) {
  return base.replace(/\/+$/, '') + '/' + segment.replace(/^\/+/, '');
}
const oauthCfg = config.oauth || {};
const OAUTH_BASE_PATH = oauthCfg.basePath || '/oauth';
const OAUTH_AUTHORIZE_PATH = oauthCfg.authorizePath || joinPath(OAUTH_BASE_PATH, 'authorize');
const OAUTH_TOKEN_PATH = oauthCfg.tokenPath || joinPath(OAUTH_BASE_PATH, 'token');
const OAUTH_DEVICE_PATH = oauthCfg.devicePath || joinPath(OAUTH_BASE_PATH, 'device_authorization');
const OAUTH_INTROSPECT_PATH = oauthCfg.introspectPath || joinPath(OAUTH_BASE_PATH, 'introspect');
const OAUTH_REVOKE_PATH = oauthCfg.revokePath || joinPath(OAUTH_BASE_PATH, 'revoke');
const OAUTH_USERINFO_PATH = oauthCfg.userinfoPath || joinPath(OAUTH_BASE_PATH, 'userinfo');
const OAUTH_JWKS_PATH = oauthCfg.jwksPath || '/.well-known/jwks.json';
const OAUTH_PUBLIC_PEM_PATH = oauthCfg.publicKeyPath || '/.well-known/public.pem';
const OAUTH_DISCOVERY_PATH = oauthCfg.discoveryPath || '/.well-known/openid_configuration';
const DEVICE_VERIFICATION_PATH = oauthCfg.deviceVerificationPath || '/device';
const DEVICE_VERIFY_PATH = oauthCfg.deviceVerifyPath || '/device/verify';

// New: load all rule files from stubs directory recursively
function loadStubRules(stubsDir) {
  const root = path.join(__dirname, stubsDir);
  const rules = [];
  function walk(dir) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        walk(full);
      } else if (/^rule.*\.json$/.test(e.name)) {
        try {
          const raw = JSON.parse(fs.readFileSync(full, 'utf8'));
          raw.__baseDir = path.dirname(full); // store for locating response file
          rules.push(raw);
        } catch (err) {
          console.error('Failed to load rule', full, err.message);
        }
      }
    }
  }
  if (fs.existsSync(root)) walk(root);
  return rules;
}

let rules = loadStubRules(config.stubsDir || 'stubs');

// Optional hot reload in dev when files change
if (process.env.WATCH_RULES === '1') {
  const watchPath = path.join(__dirname, config.stubsDir || 'stubs');
  fs.watch(watchPath, { recursive: true }, (event, filename) => {
    if (filename && /rule.*\.json$/.test(filename)) {
      console.log('Reloading stub rules due to change in', filename);
      rules = loadStubRules(config.stubsDir || 'stubs');
    }
  });
}

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// CORS
if (config.cors?.enabled) {
  app.use(cors({
    origin: config.cors.origins || '*',
    credentials: true
  }));
}

// Basic logging
app.use((req, res, next) => {
  if (config.logging) {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`);
  }
  next();
});

function requestMatchesRule(req, rule) {
  const m = rule.match || {};
  if (m.method && m.method.toUpperCase() !== req.method.toUpperCase()) return false;
  if (m.path) {
    if (m.path !== req.path) return false;
  } else if (m.pathPattern) {
    const regexp = pathToRegexp(m.pathPattern);
    if (!regexp.test(req.path)) return false;
  }
  if (m.bodyContains && Array.isArray(m.bodyContains) && req.body && Object.keys(req.body).length) {
    const bodyString = JSON.stringify(req.body);
    if (!m.bodyContains.every(token => bodyString.includes(token))) return false;
  }
  if (m.query && Object.keys(m.query).length) {
    for (const [k, v] of Object.entries(m.query)) if (req.query[k] !== String(v)) return false;
  }
  return true;
}

function extractParams(pattern, actualPath) {
  if (!pattern) return {};
  const matcher = match(pattern, { decode: decodeURIComponent });
  const m = matcher(actualPath);
  return m ? m.params : {};
}

function interpolate(obj, context) {
  if (obj == null) return obj;
  if (typeof obj === 'string') {
    return obj.replace(/{{\s*([^}]+)\s*}}/g, (_, expr) => {
      if (expr === 'Date.now') return Date.now();
      const parts = expr.split('.');
      let current = context;
      for (const p of parts) {
        if (current && Object.prototype.hasOwnProperty.call(current, p)) current = current[p]; else return '';
      }
      return current;
    });
  }
  if (Array.isArray(obj)) return obj.map(i => interpolate(i, context));
  if (typeof obj === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(obj)) out[k] = interpolate(v, context);
    return out;
  }
  return obj;
}

// Load keys for JWT
let privateKey = null;
let publicKey = null;
try {
  privateKey = fs.readFileSync(path.join(__dirname, 'keys', 'private.pem'));
  publicKey = fs.readFileSync(path.join(__dirname, 'keys', 'public.pem'));
} catch (e) {
  console.warn('JWT keys not found, JWT signing disabled');
}

// Rebuild JWKS with real modulus/exponent
const crypto = require('crypto');
let jwkCache = null;
if (publicKey) {
  try {
    const pubObj = crypto.createPublicKey(publicKey);
    const jwk = pubObj.export({ format: 'jwk' }); // {kty,n,e}
    jwkCache = {
      keys: [
        {
          kty: jwk.kty,
            use: 'sig',
            alg: 'RS256',
            kid: 'local-dev-key',
            n: jwk.n,
            e: jwk.e
        }
      ]
    };
  } catch (err) {
    console.warn('Failed to export JWKS', err.message);
  }
}

if (jwkCache) {
  app.get(OAUTH_JWKS_PATH, (req, res) => res.json(jwkCache));
  app.get(OAUTH_PUBLIC_PEM_PATH, (req, res) => res.type('text/plain').send(publicKey.toString()));
}

// In-memory refresh token store (only if using opaque tokens) – here we use JWT refresh tokens, so map optional.
const issuedRefreshTokens = new Set();
// PKCE / Authorization Code in-memory store
const authCodes = new Map(); // code -> { clientId, scope, redirectUri, codeChallenge, method, createdAt }
// Device Code Flow in-memory store
const deviceCodes = new Map(); // device_code -> { userCode, clientId, scope, verified, createdAt }

function generateRandomString(len = 32) {
  return crypto.randomBytes(len).toString('base64url').slice(0, len + 4); // extra to account for removed padding
}
function base64urlSha256(input) {
  return crypto.createHash('sha256').update(input).digest('base64').replace(/=+/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

// Client authentication helper
function authenticateClient(req) {
  const authHeader = req.headers.authorization;
  const clientId = req.body.client_id;
  const clientSecret = req.body.client_secret;
  const clientAssertion = req.body.client_assertion;
  const clientAssertionType = req.body.client_assertion_type;
  
  // Client Secret Basic (Authorization header)
  if (authHeader && authHeader.startsWith('Basic ')) {
    try {
      const credentials = Buffer.from(authHeader.substring(6), 'base64').toString('utf-8');
      const [id, secret] = credentials.split(':');
      return { clientId: id, authenticated: true, method: 'client_secret_basic' };
    } catch (err) {
      return { error: 'invalid_client', error_description: 'Invalid basic auth credentials' };
    }
  }
  
  // Client Secret Post (form parameters)
  if (clientId && clientSecret) {
    return { clientId, authenticated: true, method: 'client_secret_post' };
  }
  
  // JWT Bearer client authentication
  if (clientAssertion && clientAssertionType === 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer') {
    try {
      const decoded = jwt.verify(clientAssertion, publicKey, { algorithms: ['RS256'] });
      if (decoded.sub !== decoded.iss) {
        return { error: 'invalid_client', error_description: 'JWT assertion subject must equal issuer' };
      }
      return { clientId: decoded.sub, authenticated: true, method: 'private_key_jwt' };
    } catch (err) {
      return { error: 'invalid_client', error_description: 'Invalid JWT assertion: ' + err.message };
    }
  }
  
  // No authentication (public client)
  if (clientId) {
    return { clientId, authenticated: true, method: 'none' };
  }
  
  // For stub server: default to a generic client if no auth provided
  return { clientId: 'default-client', authenticated: true, method: 'none' };
}

// Added: helper token signing functions (were previously referenced but undefined)
function signAccessToken(claims, ttlSeconds = 3600, extraClaims = {}) {
  if (!privateKey) return 'unsigned-access-token';
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: 'stub-server',
    aud: 'stub-client',
    iat: now,
    exp: now + ttlSeconds,
    ...claims,
    ...extraClaims
  };
  return jwt.sign(payload, privateKey, { algorithm: 'RS256', keyid: 'local-dev-key' });
}
function signRefreshToken(claims, ttlSeconds = 7 * 24 * 3600) {
  return signAccessToken({ ...claims, type: 'refresh' }, ttlSeconds);
}

function signIdToken(claims, ttlSeconds = 3600) {
  if (!privateKey) return 'unsigned-id-token';
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: 'stub-server',
    aud: claims.aud || 'stub-client',
    iat: now,
    exp: now + ttlSeconds,
    sub: claims.sub || 'user123',
    auth_time: now,
    nonce: claims.nonce,
    at_hash: claims.at_hash, // Optional: hash of access token
    ...claims
  };
  return jwt.sign(payload, privateKey, { algorithm: 'RS256', keyid: 'local-dev-key' });
}

// Authorization endpoint (simplified, auto-approves user)
app.get(OAUTH_AUTHORIZE_PATH, (req, res) => {
  const { response_type, client_id, redirect_uri, scope = 'basic', state, code_challenge, code_challenge_method = 'plain', nonce } = req.query;
  
  if (!['code', 'token', 'id_token', 'code token', 'code id_token', 'token id_token', 'code token id_token'].includes(response_type)) {
    return res.status(400).json({ error: 'unsupported_response_type' });
  }
  
  if (!client_id || !redirect_uri) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'client_id and redirect_uri required' });
  }

  // Handle Authorization Code Flow
  if (response_type === 'code') {
    if (code_challenge_method && !['plain', 'S256'].includes(code_challenge_method)) {
      return res.status(400).json({ error: 'invalid_request', error_description: 'code_challenge_method must be plain or S256' });
    }
    if (code_challenge_method && !code_challenge) {
      return res.status(400).json({ error: 'invalid_request', error_description: 'code_challenge required for PKCE' });
    }

    const code = generateRandomString(40);
    authCodes.set(code, { 
      clientId: client_id, 
      scope, 
      redirectUri: redirect_uri, 
      codeChallenge: code_challenge, 
      method: code_challenge_method, 
      createdAt: Date.now() 
    });

    const qp = new URLSearchParams({ code });
    if (state) qp.append('state', state);

    return res.redirect(302, `${redirect_uri}${redirect_uri.includes('?') ? '&' : '?'}${qp.toString()}`);
  }

  // Handle Implicit Flow
  if (response_type === 'token') {
    if (!privateKey) {
      return res.status(500).json({ error: 'server_not_configured', error_description: 'JWT keys missing' });
    }

    const accessToken = signAccessToken({ sub: client_id, scope, grant: 'implicit' }, 3600);
    const qp = new URLSearchParams({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: '3600',
      scope
    });
    if (state) qp.append('state', state);

    // Fragment response for implicit flow
    return res.redirect(302, `${redirect_uri}#${qp.toString()}`);
  }

  // Handle OpenID Connect flows (id_token responses)
  if (response_type.includes('id_token')) {
    if (!privateKey) {
      return res.status(500).json({ error: 'server_not_configured', error_description: 'JWT keys missing' });
    }

    const qp = new URLSearchParams();
    const responseTypes = response_type.split(' ');
    
    if (responseTypes.includes('code')) {
      const code = generateRandomString(40);
      authCodes.set(code, { 
        clientId: client_id, 
        scope, 
        redirectUri: redirect_uri, 
        codeChallenge: code_challenge, 
        method: code_challenge_method, 
        nonce,
        createdAt: Date.now() 
      });
      qp.append('code', code);
    }

    if (responseTypes.includes('token')) {
      const accessToken = signAccessToken({ sub: client_id, scope, grant: 'implicit' }, 3600);
      qp.append('access_token', accessToken);
      qp.append('token_type', 'Bearer');
      qp.append('expires_in', '3600');
    }

    if (responseTypes.includes('id_token')) {
      const idToken = signIdToken({ sub: client_id, aud: client_id, nonce }, 3600);
      qp.append('id_token', idToken);
    }

    if (state) qp.append('state', state);

    // Fragment response for flows containing id_token
    return res.redirect(302, `${redirect_uri}#${qp.toString()}`);
  }

  return res.status(400).json({ error: 'unsupported_response_type' });
});
// Optional POST support
app.post(OAUTH_AUTHORIZE_PATH, express.urlencoded({ extended: false }), (req, res) => {
  req.query = { ...req.body }; // normalize
  return app._router.handle(req, res, () => {}); // re-dispatch as GET logic
});

// Device Authorization Grant endpoint (RFC 8628)
app.post(OAUTH_DEVICE_PATH, (req, res) => {
  const { client_id, scope = 'basic' } = req.body;
  if (!client_id) {
    return res.status(400).json({ 
      error: 'invalid_request', 
      error_description: 'client_id is required' 
    });
  }

  const deviceCode = generateRandomString(32);
  const userCode = generateRandomString(8).toUpperCase().substring(0, 8);
  const verificationUri = `http://localhost:${process.env.PORT || config.port || 3000}${DEVICE_VERIFICATION_PATH}`;
  const verificationUriComplete = `${verificationUri}?user_code=${userCode}`;
  const expiresIn = 1800; // 30 minutes
  const interval = 5; // 5 seconds polling interval

  deviceCodes.set(deviceCode, {
    userCode,
    clientId: client_id,
    scope,
    verified: false,
    createdAt: Date.now()
  });

  // Auto-approve after 10 seconds for stub purposes
  setTimeout(() => {
    const stored = deviceCodes.get(deviceCode);
    if (stored) {
      stored.verified = true;
      stored.approvedAt = Date.now();
    }
  }, 10000);

  res.json({
    device_code: deviceCode,
    user_code: userCode,
    verification_uri: verificationUri,
    verification_uri_complete: verificationUriComplete,
    expires_in: expiresIn,
    interval
  });
});

// Device verification page (simple HTML for user to approve)
app.get(DEVICE_VERIFICATION_PATH, (req, res) => {
  const userCode = req.query.user_code;
  const html = `
    <!DOCTYPE html>
    <html>
    <head><title>Device Authorization</title></head>
    <body>
      <h1>Device Authorization</h1>
      <p>Please enter the code displayed on your device:</p>
      <form method="post" action="${DEVICE_VERIFY_PATH}">
        <input type="text" name="user_code" value="${userCode || ''}" placeholder="Enter code" required>
        <button type="submit">Authorize</button>
      </form>
    </body>
    </html>
  `;
  res.send(html);
});

app.post(DEVICE_VERIFY_PATH, express.urlencoded({ extended: false }), (req, res) => {
  const { user_code } = req.body;
  const deviceEntry = Array.from(deviceCodes.values()).find(d => d.userCode === user_code);
  
  if (deviceEntry) {
    deviceEntry.verified = true;
    deviceEntry.approvedAt = Date.now();
    res.send('<h1>Device Authorized Successfully!</h1><p>You can now close this window.</p>');
  } else {
    res.status(400).send('<h1>Invalid Code</h1><p>The code you entered is invalid or expired.</p>');
  }
});
// OAuth2 token endpoint (form-urlencoded or JSON)
app.post(OAUTH_TOKEN_PATH, (req, res) => {
  if (!privateKey) return res.status(500).json({ error: 'server_not_configured', error_description: 'JWT keys missing' });
  
  // Authenticate client
  const clientAuth = authenticateClient(req);
  if (clientAuth.error) {
    return res.status(401).json({ error: clientAuth.error, error_description: clientAuth.error_description });
  }
  
  const grantType = req.body.grant_type || req.body.grantType;
  const scope = (req.body.scope || 'basic').split(/\s+/).filter(Boolean).join(' ');
  const clientId = clientAuth.clientId;
  const username = req.body.username;
  const refreshTokenInput = req.body.refresh_token;
  const accessTTL = 3600;
  const refreshTTL = 7 * 24 * 3600; // 7 days

  try {
    if (grantType === 'password') {
      if (!username) return res.status(400).json({ error: 'invalid_request', error_description: 'username required' });
      const accessToken = signAccessToken({ sub: username, scope }, accessTTL, {});
      const refreshToken = signRefreshToken({ sub: username, scope }, refreshTTL);
      issuedRefreshTokens.add(refreshToken);
      return res.json({
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: accessTTL,
        refresh_token: refreshToken,
        scope
      });
    } else if (grantType === 'client_credentials') {
      const accessToken = signAccessToken({ sub: clientId, scope, grant: 'client_credentials' }, accessTTL);
      return res.json({
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: accessTTL,
        scope
      });
    } else if (grantType === 'refresh_token') {
      if (!refreshTokenInput) return res.status(400).json({ error: 'invalid_request', error_description: 'refresh_token required' });
      try {
        const decoded = jwt.verify(refreshTokenInput, publicKey, { algorithms: ['RS256'] });
        if (decoded.type !== 'refresh') return res.status(400).json({ error: 'invalid_grant', error_description: 'Not a refresh token' });
        // Optional rotation: issue new refresh token
        const newRefresh = signRefreshToken({ sub: decoded.sub, scope: decoded.scope }, refreshTTL);
        const newAccess = signAccessToken({ sub: decoded.sub, scope: decoded.scope }, accessTTL);
        issuedRefreshTokens.add(newRefresh);
        return res.json({
          access_token: newAccess,
          token_type: 'Bearer',
          expires_in: accessTTL,
          refresh_token: newRefresh,
          scope: decoded.scope
        });
      } catch (err) {
        return res.status(400).json({ error: 'invalid_grant', error_description: 'refresh token invalid' });
      }
    } else if (grantType === 'authorization_code') {
      const code = req.body.code;
      const verifier = req.body.code_verifier;
      const redirectUri = req.body.redirect_uri;
      if (!code || !verifier || !redirectUri) return res.status(400).json({ error: 'invalid_request', error_description: 'code, code_verifier, redirect_uri required' });
      const stored = authCodes.get(code);
      if (!stored) return res.status(400).json({ error: 'invalid_grant', error_description: 'code invalid or expired' });
      if (stored.redirectUri !== redirectUri) return res.status(400).json({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' });
      // PKCE validation with verbose debug when mismatch
      if (stored.codeChallenge) {
        let computed;
        if (stored.method === 'S256') {
          computed = base64urlSha256(verifier);
          if (computed !== stored.codeChallenge) {
            console.warn('PKCE S256 mismatch', { submitted_verifier: verifier, computed, expected: stored.codeChallenge, method: stored.method });
            return res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' });
          }
        } else { // plain
          computed = verifier;
          if (verifier !== stored.codeChallenge) {
            console.warn('PKCE plain mismatch', { submitted_verifier: verifier, expected: stored.codeChallenge, method: stored.method });
            return res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' });
          }
        }
      }
      authCodes.delete(code); // one-time use
      const accessTTL = 3600;
      const refreshTTL = 7 * 24 * 3600;
      const accessToken = signAccessToken({ sub: stored.clientId, scope: stored.scope, grant: 'authorization_code' }, accessTTL);
      const refreshToken = signRefreshToken({ sub: stored.clientId, scope: stored.scope }, refreshTTL);
      issuedRefreshTokens.add(refreshToken);
      
      const tokenResponse = {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: accessTTL,
        refresh_token: refreshToken,
        scope: stored.scope
      };
      
      // Add ID token if OpenID Connect scope is requested
      if (stored.scope && stored.scope.includes('openid')) {
        const idToken = signIdToken({ 
          sub: stored.clientId, 
          aud: stored.clientId, 
          nonce: stored.nonce,
          at_hash: crypto.createHash('sha256').update(accessToken.split('.')[0]).digest('base64').substring(0, 16)
        }, accessTTL);
        tokenResponse.id_token = idToken;
      }
      
      return res.json(tokenResponse);
    } else if (grantType === 'urn:ietf:params:oauth:grant-type:jwt-bearer') {
      const assertion = req.body.assertion;
      if (!assertion) return res.status(400).json({ error: 'invalid_request', error_description: 'assertion required' });
      
      try {
        // Verify the JWT assertion (for stub purposes, we'll accept any valid JWT)
        const decoded = jwt.verify(assertion, publicKey, { algorithms: ['RS256'] });
        
        // In a real implementation, you'd validate the issuer, audience, and other claims
        if (!decoded.sub) {
          return res.status(400).json({ error: 'invalid_grant', error_description: 'assertion missing subject' });
        }
        
        const accessToken = signAccessToken({ 
          sub: decoded.sub, 
          scope, 
          grant: 'jwt-bearer',
          original_issuer: decoded.iss 
        }, accessTTL);
        
        return res.json({
          access_token: accessToken,
          token_type: 'Bearer',
          expires_in: accessTTL,
          scope
        });
      } catch (err) {
        return res.status(400).json({ error: 'invalid_grant', error_description: 'assertion invalid: ' + err.message });
      }
    } else if (grantType === 'urn:ietf:params:oauth:grant-type:device_code') {
      const deviceCode = req.body.device_code;
      if (!deviceCode) return res.status(400).json({ error: 'invalid_request', error_description: 'device_code required' });
      
      const stored = deviceCodes.get(deviceCode);
      if (!stored) return res.status(400).json({ error: 'invalid_grant', error_description: 'device code invalid or expired' });
      
      // Check if code has expired (30 minutes)
      if (Date.now() - stored.createdAt > 1800000) {
        deviceCodes.delete(deviceCode);
        return res.status(400).json({ error: 'expired_token', error_description: 'device code has expired' });
      }
      
      if (!stored.verified) {
        return res.status(400).json({ error: 'authorization_pending', error_description: 'User has not yet approved the device' });
      }
      
      deviceCodes.delete(deviceCode); // one-time use
      const accessToken = signAccessToken({ sub: stored.clientId, scope: stored.scope, grant: 'device_code' }, accessTTL);
      const refreshToken = signRefreshToken({ sub: stored.clientId, scope: stored.scope }, refreshTTL);
      issuedRefreshTokens.add(refreshToken);
      
      return res.json({
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: accessTTL,
        refresh_token: refreshToken,
        scope: stored.scope
      });
    } else {
      return res.status(400).json({ error: 'unsupported_grant_type', error_description: grantType + ' not supported' });
    }
  } catch (e) {
    console.error('OAuth token error', e);
    return res.status(500).json({ error: 'server_error' });
  }
});

// Token Introspection endpoint (RFC 7662)
app.post(OAUTH_INTROSPECT_PATH, (req, res) => {
  const token = req.body.token;
  const tokenTypeHint = req.body.token_type_hint; // 'access_token' or 'refresh_token'
  
  if (!token) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'token parameter required' });
  }
  
  try {
    const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
    const now = Math.floor(Date.now() / 1000);
    
    // Check if token is expired
    if (decoded.exp && decoded.exp < now) {
      return res.json({ active: false });
    }
    
    // Return token introspection response
    return res.json({
      active: true,
      scope: decoded.scope || 'basic',
      client_id: decoded.aud || 'stub-client',
      username: decoded.sub,
      token_type: decoded.type === 'refresh' ? 'refresh_token' : 'access_token',
      exp: decoded.exp,
      iat: decoded.iat,
      sub: decoded.sub,
      aud: decoded.aud,
      iss: decoded.iss,
      jti: decoded.jti
    });
  } catch (err) {
    // Token is invalid or malformed
    return res.json({ active: false });
  }
});

// Token Revocation endpoint (RFC 7009)
app.post(OAUTH_REVOKE_PATH, (req, res) => {
  const token = req.body.token;
  const tokenTypeHint = req.body.token_type_hint; // 'access_token' or 'refresh_token'
  
  if (!token) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'token parameter required' });
  }
  
  try {
    // For JWTs, we can't really "revoke" them since they're stateless
    // In a real implementation, you'd maintain a blacklist
    // For this stub, we'll just remove from our refresh token store if it exists
    if (issuedRefreshTokens.has(token)) {
      issuedRefreshTokens.delete(token);
    }
    
    // Always return 200 OK for successful revocation (even if token was already invalid)
    return res.status(200).send();
  } catch (err) {
    // Even if there's an error, RFC 7009 says to return 200
    return res.status(200).send();
  }
});

// OpenID Connect UserInfo endpoint
app.get(OAUTH_USERINFO_PATH, (req, res) => {
  // Handle both GET and POST
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'invalid_token', error_description: 'Bearer token required' });
  }
  
  const token = authHeader.substring(7);
  try {
    const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
    const now = Math.floor(Date.now() / 1000);
    
    if (decoded.exp && decoded.exp < now) {
      return res.status(401).json({ error: 'invalid_token', error_description: 'Token expired' });
    }
    
    // Return user info (stub data)
    return res.json({
      sub: decoded.sub,
      name: 'John Doe',
      given_name: 'John',
      family_name: 'Doe',
      preferred_username: decoded.sub,
      email: `${decoded.sub}@example.com`,
      email_verified: true,
      picture: 'https://via.placeholder.com/150',
      updated_at: Math.floor(Date.now() / 1000)
    });
  } catch (err) {
    return res.status(401).json({ error: 'invalid_token', error_description: 'Token invalid' });
  }
});

app.post(OAUTH_USERINFO_PATH, (req, res) => {
  // Handle both GET and POST - reuse GET logic
  return app._router.handle({ ...req, method: 'GET' }, res, () => {});
});

// OpenID Connect Discovery endpoint
app.get(OAUTH_DISCOVERY_PATH, (req, res) => {
  const baseUrl = `http://localhost:${process.env.PORT || 3000}`;
  
  res.json({
    issuer: baseUrl,
    authorization_endpoint: baseUrl + OAUTH_AUTHORIZE_PATH,
    token_endpoint: baseUrl + OAUTH_TOKEN_PATH,
    userinfo_endpoint: baseUrl + OAUTH_USERINFO_PATH,
    jwks_uri: baseUrl + OAUTH_JWKS_PATH,
    device_authorization_endpoint: baseUrl + OAUTH_DEVICE_PATH,
    introspection_endpoint: baseUrl + OAUTH_INTROSPECT_PATH,
    revocation_endpoint: baseUrl + OAUTH_REVOKE_PATH,
    response_types_supported: [
      'code',
      'token',
      'id_token',
      'code token',
      'code id_token',
      'token id_token',
      'code token id_token'
    ],
    grant_types_supported: [
      'authorization_code',
      'implicit',
      'password',
      'client_credentials',
      'refresh_token',
      'urn:ietf:params:oauth:grant-type:device_code',
      'urn:ietf:params:oauth:grant-type:jwt-bearer'
    ],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    scopes_supported: ['openid', 'profile', 'email', 'basic'],
    token_endpoint_auth_methods_supported: [
      'client_secret_basic',
      'client_secret_post',
      'none'
    ],
    code_challenge_methods_supported: ['plain', 'S256'],
    claims_supported: [
      'sub',
      'name',
      'given_name',
      'family_name',
      'preferred_username',
      'email',
      'email_verified',
      'picture',
      'updated_at'
    ]
  });
});

// Wrap original interpolate for Date.now already handled
// After body interpolation but before sending, inject signed tokens for oauth responses
app.use(async (req, res, next) => {
  try {
    const matchedRule = rules.find(r => requestMatchesRule(req, r));
    if (!matchedRule) return next();
    const responseRel = matchedRule.response.file; // now relative to rule directory
    const abs = path.join(matchedRule.__baseDir, responseRel);
    if (!fs.existsSync(abs)) {
      console.warn('Response file not found:', abs);
      return res.status(500).json({ error: 'Configured response file missing' });
    }
    const raw = JSON.parse(fs.readFileSync(abs, 'utf8'));
    const params = extractParams(matchedRule.match.pathPattern, req.path);
    const context = { params, query: req.query, body: req.body };
    let body = interpolate(raw.body, context);

    // JWT signing logic for OAuth token endpoint
    if (privateKey && req.path === OAUTH_TOKEN_PATH && body && body.access_token) {
      const nowSec = Math.floor(Date.now() / 1000);
      const payload = {
        iss: 'stub-server',
        sub: 'user-or-client',
        aud: 'stub-client',
        iat: nowSec,
        exp: nowSec + (body.expires_in || 3600),
        scope: body.scope
      };
      try {
        body.access_token = jwt.sign(payload, privateKey, { algorithm: 'RS256', keyid: 'local-dev-key' });
        if (body.refresh_token) {
          body.refresh_token = jwt.sign({ ...payload, exp: nowSec + 86400, type: 'refresh' }, privateKey, { algorithm: 'RS256', keyid: 'local-dev-key' });
        }
      } catch (err) {
        console.error('JWT signing failed', err.message);
      }
    }

    const delay = (raw.delayMs != null ? raw.delayMs : matchedRule.response.delayMs) ?? config.globalDelayMs ?? 0;
    const status = raw.status || 200;
    if (delay > 0) await new Promise(r => setTimeout(r, delay));
    return res.status(status).json(body);
  } catch (err) {
    console.error('Stub handling error', err);
    return res.status(500).json({ error: 'Stub server internal error' });
  }
});

// Added explicit health endpoint for Postman PKCE Step 1
app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.use((req, res) => {
  const fb = config.fallback || { status: 404, json: { error: 'Not found' } };
  res.status(fb.status || 404).json(fb.json || { error: 'Not found' });
});

const port = process.env.PORT || config.port || 3000;
app.listen(port, () => {
  console.log(`Stub server running on http://localhost:${port}`);
  console.log(`Config: ${CONFIG_FILE}`);
  console.log(`Stubs dir: ${config.stubsDir || 'stubs'}`);
  console.log(`Rules loaded: ${rules.length}`);
  console.log('');
  console.log('OAuth2 & OpenID Connect Endpoints:');
  console.log(`  Authorization: ${OAUTH_AUTHORIZE_PATH}`);
  console.log(`  Token: ${OAUTH_TOKEN_PATH}`);
  console.log(`  Device Authorization: ${OAUTH_DEVICE_PATH}`);
  console.log(`  Token Introspection: ${OAUTH_INTROSPECT_PATH}`);
  console.log(`  Token Revocation: ${OAUTH_REVOKE_PATH}`);
  console.log(`  UserInfo: ${OAUTH_USERINFO_PATH}`);
  console.log(`  Discovery: ${OAUTH_DISCOVERY_PATH}`);
  console.log(`  JWKS: ${OAUTH_JWKS_PATH}`);
  console.log(`  Public Key: ${OAUTH_PUBLIC_PEM_PATH}`);
  console.log(`  Device Verification: ${DEVICE_VERIFICATION_PATH}`);
  console.log(`  Device Verify: ${DEVICE_VERIFY_PATH}`);
  console.log('');
  console.log('💡 All endpoint paths are configurable in config/local.json');
  console.log('');
  console.log('Supported OAuth2 Flows:');
  console.log('  ✓ Authorization Code Flow (with PKCE)');
  console.log('  ✓ Implicit Flow');
  console.log('  ✓ Resource Owner Password Credentials Flow');
  console.log('  ✓ Client Credentials Flow');
  console.log('  ✓ Refresh Token Flow');
  console.log('  ✓ Device Authorization Grant (RFC 8628)');
  console.log('  ✓ JWT Bearer Grant (RFC 7523)');
  console.log('  ✓ OpenID Connect (ID tokens, UserInfo, Discovery)');
  console.log('');
  console.log('Client Authentication Methods:');
  console.log('  ✓ client_secret_basic (Authorization header)');
  console.log('  ✓ client_secret_post (form parameters)');
  console.log('  ✓ private_key_jwt (JWT assertion)');
  console.log('  ✓ none (public clients)');
});
