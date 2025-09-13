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
const OAUTH_JWKS_PATH = oauthCfg.jwksPath || '/.well-known/jwks.json';
const OAUTH_PUBLIC_PEM_PATH = oauthCfg.publicKeyPath || '/.well-known/public.pem';

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

function generateRandomString(len = 32) {
  return crypto.randomBytes(len).toString('base64url').slice(0, len + 4); // extra to account for removed padding
}
function base64urlSha256(input) {
  return crypto.createHash('sha256').update(input).digest('base64').replace(/=+/g, '').replace(/\+/g, '-').replace(/\//g, '_');
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

// Authorization endpoint (simplified, auto-approves user)
app.get(OAUTH_AUTHORIZE_PATH, (req, res) => {
  const { response_type, client_id, redirect_uri, scope = 'basic', state, code_challenge, code_challenge_method = 'plain' } = req.query;
  if (response_type !== 'code') return res.status(400).json({ error: 'unsupported_response_type' });
  if (!client_id || !redirect_uri) return res.status(400).json({ error: 'invalid_request', error_description: 'client_id and redirect_uri required' });
  if (code_challenge_method && !['plain', 'S256'].includes(code_challenge_method)) return res.status(400).json({ error: 'invalid_request', error_description: 'code_challenge_method must be plain or S256' });
  if (code_challenge_method && !code_challenge) return res.status(400).json({ error: 'invalid_request', error_description: 'code_challenge required for PKCE' });

  const code = generateRandomString(40);
  authCodes.set(code, { clientId: client_id, scope, redirectUri: redirect_uri, codeChallenge: code_challenge, method: code_challenge_method, createdAt: Date.now() });

  const qp = new URLSearchParams({ code });
  if (state) qp.append('state', state);

  // Redirect with code
  return res.redirect(302, `${redirect_uri}${redirect_uri.includes('?') ? '&' : '?'}${qp.toString()}`);
});
// Optional POST support
app.post(OAUTH_AUTHORIZE_PATH, express.urlencoded({ extended: false }), (req, res) => {
  req.query = { ...req.body }; // normalize
  return app._router.handle(req, res, () => {}); // re-dispatch as GET logic
});
// OAuth2 token endpoint (form-urlencoded or JSON)
app.post(OAUTH_TOKEN_PATH, (req, res) => {
  if (!privateKey) return res.status(500).json({ error: 'server_not_configured', error_description: 'JWT keys missing' });
  const grantType = req.body.grant_type || req.body.grantType;
  const scope = (req.body.scope || 'basic').split(/\s+/).filter(Boolean).join(' ');
  const clientId = req.body.client_id || 'client';
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
  console.log(`OAuth authorize path: ${OAUTH_AUTHORIZE_PATH}`);
  console.log(`OAuth token path: ${OAUTH_TOKEN_PATH}`);
  console.log(`JWKS path: ${OAUTH_JWKS_PATH}`);
});
