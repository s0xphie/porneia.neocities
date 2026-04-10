// ═══════════════════════════════════════════════════════════════
//  AT Protocol OAuth Client for Static Sites
//  Handles: handle resolution, DID resolution, auth server
//  discovery, DPoP keypair + JWT, PKCE, PAR, token exchange
// ═══════════════════════════════════════════════════════════════

const ATPROTO_OAUTH = (() => {
  // Auto-detect: use localhost loopback client for local dev,
  // production client_id when served from neocities
  const IS_PROD = location.hostname === 'porneia.neocities.org';
  const IS_LOCAL = location.hostname === 'localhost' || location.hostname === '127.0.0.1';
  const LOCAL_REDIRECT = 'http://127.0.0.1:' + (location.port || '80') + '/';
  const CLIENT_ID = IS_PROD
    ? 'https://porneia.neocities.org/client-metadata.json'
    : IS_LOCAL
      ? 'http://localhost?redirect_uri=' + encodeURIComponent(LOCAL_REDIRECT) + '&scope=' + encodeURIComponent('atproto transition:generic')
      : 'https://porneia.neocities.org/client-metadata.json';
  const REDIRECT_URI = IS_PROD
    ? 'https://porneia.neocities.org/'
    : IS_LOCAL
      ? LOCAL_REDIRECT
      : 'https://porneia.neocities.org/';
  const SCOPE = 'atproto transition:generic';

  // ── Utilities ──────────────────────────────────────────────

  function base64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let str = '';
    for (const b of bytes) str += String.fromCharCode(b);
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function randomString(len) {
    const arr = new Uint8Array(len);
    crypto.getRandomValues(arr);
    return base64url(arr);
  }

  async function sha256(str) {
    return crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  }

  function cleanUrl(url) {
    const u = new URL(url);
    u.search = '';
    u.hash = '';
    return u.toString();
  }

  // ── DPoP Keypair ──────────────────────────────────────────

  async function generateDPoPKeyPair() {
    return crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );
  }

  async function exportKeyPair(kp) {
    return {
      privateJwk: await crypto.subtle.exportKey('jwk', kp.privateKey),
      publicJwk: await crypto.subtle.exportKey('jwk', kp.publicKey)
    };
  }

  async function importPrivateKey(jwk) {
    return crypto.subtle.importKey(
      'jwk', jwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false, ['sign']
    );
  }

  // ── DPoP Proof JWT ────────────────────────────────────────

  async function createDPoPProof(privateKey, publicJwk, method, url, nonce, ath) {
    const header = {
      typ: 'dpop+jwt',
      alg: 'ES256',
      jwk: { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x, y: publicJwk.y }
    };
    const payload = {
      jti: randomString(16),
      htm: method,
      htu: cleanUrl(url),
      iat: Math.floor(Date.now() / 1000)
    };
    if (nonce) payload.nonce = nonce;
    if (ath) payload.ath = ath;

    const hdrB64 = base64url(new TextEncoder().encode(JSON.stringify(header)));
    const plB64 = base64url(new TextEncoder().encode(JSON.stringify(payload)));
    const sig = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      privateKey,
      new TextEncoder().encode(hdrB64 + '.' + plB64)
    );
    return hdrB64 + '.' + plB64 + '.' + base64url(sig);
  }

  // ── PKCE ──────────────────────────────────────────────────

  async function generatePKCE() {
    const verifier = randomString(32);
    const challenge = base64url(await sha256(verifier));
    return { verifier, challenge };
  }

  // ── Handle / DID Resolution ───────────────────────────────

  async function resolveHandle(handle) {
    handle = handle.replace(/^@/, '').trim();
    if (!handle.includes('.')) handle += '.bsky.social';

    // Method 1: XRPC resolveHandle via public API
    try {
      const r = await fetch(
        'https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?handle=' +
        encodeURIComponent(handle)
      );
      if (r.ok) { const d = await r.json(); return { did: d.did, handle }; }
    } catch (_) {}

    // Method 2: .well-known on the handle domain
    try {
      const r = await fetch('https://' + handle + '/.well-known/atproto-did');
      if (r.ok) {
        const did = (await r.text()).trim();
        if (did.startsWith('did:')) return { did, handle };
      }
    } catch (_) {}

    throw new Error('Could not resolve handle: ' + handle);
  }

  async function resolveDID(did) {
    if (did.startsWith('did:plc:')) {
      const r = await fetch('https://plc.directory/' + did);
      if (!r.ok) throw new Error('PLC directory error: ' + r.status);
      return r.json();
    }
    if (did.startsWith('did:web:')) {
      const domain = did.slice(8).replace(/:/g, '/');
      const r = await fetch('https://' + domain + '/.well-known/did.json');
      if (!r.ok) throw new Error('DID web error: ' + r.status);
      return r.json();
    }
    throw new Error('Unsupported DID method');
  }

  function getPDS(didDoc) {
    const svc = didDoc.service && didDoc.service.find(s => s.id === '#atproto_pds');
    if (!svc) throw new Error('No #atproto_pds service in DID document');
    return svc.serviceEndpoint;
  }

  async function discoverAuthServer(pdsUrl) {
    // Step 1: Get protected resource metadata from PDS (RFC 9728)
    const prUrl = pdsUrl + '/.well-known/oauth-protected-resource';
    const prResp = await fetch(prUrl);
    if (!prResp.ok) throw new Error('Protected resource discovery failed: ' + prResp.status);
    const prMeta = await prResp.json();

    // Step 2: Get the authorization server URL from the PDS metadata
    const authServers = prMeta.authorization_servers;
    if (!authServers || !authServers.length) {
      throw new Error('No authorization_servers in PDS protected resource metadata');
    }
    const authServerUrl = authServers[0];

    // Step 3: Fetch the authorization server metadata
    const r = await fetch(authServerUrl + '/.well-known/oauth-authorization-server');
    if (!r.ok) throw new Error('Auth server metadata fetch failed: ' + r.status);
    return r.json();
  }

  // ── Fetch with DPoP nonce retry ───────────────────────────

  async function dpopFetch(url, method, privateKey, publicJwk, body, nonce) {
    const proof = await createDPoPProof(privateKey, publicJwk, method, url, nonce);
    const headers = { 'DPoP': proof };
    if (body) headers['Content-Type'] = 'application/x-www-form-urlencoded';

    let resp = await fetch(url, { method, headers, body });

    // Retry with server-provided nonce if required
    if (resp.status === 400 || resp.status === 401) {
      const newNonce = resp.headers.get('DPoP-Nonce');
      if (newNonce) {
        const proof2 = await createDPoPProof(privateKey, publicJwk, method, url, newNonce);
        const headers2 = { 'DPoP': proof2 };
        if (body) headers2['Content-Type'] = 'application/x-www-form-urlencoded';
        resp = await fetch(url, { method, headers: headers2, body });
      }
    }
    return resp;
  }

  // ── OAuth: Start Login ────────────────────────────────────

  async function startLogin(handle) {
    // 1. Resolve handle → DID
    const { did, handle: resolvedHandle } = await resolveHandle(handle);

    // 2. Resolve DID → PDS
    const didDoc = await resolveDID(did);
    const pdsUrl = getPDS(didDoc);

    // 3. Discover auth server
    const authMeta = await discoverAuthServer(pdsUrl);

    // 4. Generate DPoP keypair
    const keyPair = await generateDPoPKeyPair();
    const exported = await exportKeyPair(keyPair);

    // 5. PKCE
    const pkce = await generatePKCE();

    // 6. State
    const state = randomString(16);

    // 7. Save auth state across redirect
    sessionStorage.setItem('atproto_auth', JSON.stringify({
      did, handle: resolvedHandle, pdsUrl, state,
      codeVerifier: pkce.verifier,
      privateJwk: exported.privateJwk,
      publicJwk: exported.publicJwk,
      tokenEndpoint: authMeta.token_endpoint,
      issuer: authMeta.issuer
    }));

    // 8. PAR (Pushed Authorization Request)
    const parUrl = authMeta.pushed_authorization_request_endpoint;
    const parBody = new URLSearchParams({
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      code_challenge: pkce.challenge,
      code_challenge_method: 'S256',
      scope: SCOPE,
      response_type: 'code',
      state: state,
      login_hint: did
    });

    const parResp = await dpopFetch(parUrl, 'POST', keyPair.privateKey, exported.publicJwk, parBody);
    if (!parResp.ok) {
      const err = await parResp.text();
      throw new Error('PAR failed (' + parResp.status + '): ' + err);
    }
    const parData = await parResp.json();

    // Save DPoP-Nonce if server provided one
    const dpopNonce = parResp.headers.get('DPoP-Nonce');
    if (dpopNonce) {
      const st = JSON.parse(sessionStorage.getItem('atproto_auth'));
      st.dpopNonce = dpopNonce;
      sessionStorage.setItem('atproto_auth', JSON.stringify(st));
    }

    // 9. Redirect to authorization endpoint
    const authUrl = new URL(authMeta.authorization_endpoint);
    authUrl.searchParams.set('client_id', CLIENT_ID);
    authUrl.searchParams.set('request_uri', parData.request_uri);

    window.location.href = authUrl.toString();
  }

  // ── OAuth: Handle Callback ────────────────────────────────

  async function handleCallback() {
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const state = params.get('state');
    const iss = params.get('iss');
    const error = params.get('error');

    if (!code && !error) return null;

    // Clean the URL
    window.history.replaceState({}, '', window.location.pathname);

    if (error) {
      const desc = params.get('error_description') || error;
      throw new Error('Authorization denied: ' + desc);
    }

    const authState = JSON.parse(sessionStorage.getItem('atproto_auth'));
    if (!authState) throw new Error('No auth state found — try logging in again');

    // Verify state
    if (state !== authState.state) throw new Error('State mismatch');

    // Verify issuer
    if (iss && iss !== authState.issuer) throw new Error('Issuer mismatch');

    // Import DPoP key
    const privateKey = await importPrivateKey(authState.privateJwk);

    // Exchange code for tokens
    const tokenBody = new URLSearchParams({
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      code_verifier: authState.codeVerifier
    });

    const tokenResp = await dpopFetch(
      authState.tokenEndpoint, 'POST',
      privateKey, authState.publicJwk,
      tokenBody, authState.dpopNonce
    );

    if (!tokenResp.ok) {
      const err = await tokenResp.text();
      throw new Error('Token exchange failed (' + tokenResp.status + '): ' + err);
    }

    const tokenData = await tokenResp.json();

    // Build session
    const session = {
      did: tokenData.sub || authState.did,
      handle: authState.handle,
      pdsUrl: authState.pdsUrl,
      authenticatedAt: Date.now()
    };

    localStorage.setItem('atproto_session', JSON.stringify(session));
    sessionStorage.removeItem('atproto_auth');

    return session;
  }

  // ── Session Management ────────────────────────────────────

  function getSession() {
    try {
      return JSON.parse(localStorage.getItem('atproto_session'));
    } catch (_) {
      return null;
    }
  }

  function logout() {
    localStorage.removeItem('atproto_session');
    sessionStorage.removeItem('atproto_auth');
    window.location.reload();
  }

  // ── Public Profile (unauthenticated, public API) ──────────

  async function getProfile(did) {
    try {
      const r = await fetch(
        'https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=' +
        encodeURIComponent(did)
      );
      if (r.ok) return r.json();
    } catch (_) {}
    return null;
  }

  return { startLogin, handleCallback, getSession, logout, getProfile };
})();
