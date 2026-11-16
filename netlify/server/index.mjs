import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { createHash, randomBytes, randomUUID, scrypt, timingSafeEqual } from 'node:crypto';
import { extname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import WebSocket, { WebSocketServer } from 'ws';
import { drizzle } from 'drizzle-orm/netlify-db';
import { sql } from 'drizzle-orm';
const HOST = process.env.HOST || '0.0.0.0';
const PUBLIC_DIR = resolve(fileURLToPath(new URL('../../public', import.meta.url)));
const PORT = Number(process.env.PORT || 8889);
const db = process.env.NETLIFY_DB_URL ? drizzle() : null;
const scryptAsync = promisify(scrypt);
const DUMMY_ACCOUNT_SALT = randomBytes(16).toString('hex');
const MAX_PLAYERS = 64;
const MAX_NAME = 14;
const MAX_STATE_LEN = 120;
const STATE_PER_SEC = 45;
const MAX_VOICE_LEN = 12000;
const MAX_GIFT_LEN = 240;
const HEARTBEAT_MS = 30000;
const ADMIN_SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const PLAYER_SESSION_TTL_SECONDS = 30 * 24 * 60 * 60;
const ACCOUNT_SERVICE_ERROR = 'Account service unavailable. Link Netlify Database and deploy the account migration.';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || '';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const adminSessions = new Map();
const adminLoginAttempts = new Map();
const accountLoginAttempts = new Map();
const accountSignups = new Map();

function isAdminSession(token) {
  const expiresAt = adminSessions.get(token);
  if (!expiresAt) return false;
  if (expiresAt <= Date.now()) {
    adminSessions.delete(token);
    return false;
  }
  return true;
}

function safeCredentialMatch(value, expected) {
  const actualHash = createHash('sha256').update(value).digest();
  const expectedHash = createHash('sha256').update(expected).digest();
  return timingSafeEqual(actualHash, expectedHash);
}

function adminSessionFromCookie(cookie = '') {
  const token = cookie.match(/(?:^|; )shiftlab_admin=([a-f0-9]{64})(?:;|$)/)?.[1];
  return token && isAdminSession(token) ? token : null;
}

function playerSessionFromCookie(cookie = '') {
  return cookie.match(/(?:^|; )shiftlab_account=([a-f0-9]{64})(?:;|$)/)?.[1] || null;
}

function hashSessionToken(token) {
  return createHash('sha256').update(token).digest('hex');
}

async function playerFromCookie(cookie) {
  const token = playerSessionFromCookie(cookie);
  if (!token || !db) return null;
  const sessionHash = hashSessionToken(token);
  const result = await db.execute(sql`
    select accounts.id as id, accounts.username as username
    from player_sessions sessions
    join player_accounts accounts on accounts.id = sessions.player_id
    where sessions.token_hash = ${sessionHash} and sessions.expires_at > now()
  `);
  const account = result.rows[0];
  return account ? { id: account.id, username: account.username, sessionHash } : null;
}

async function readJsonBody(req, maxBytes) {
  let body = '';
  for await (const chunk of req) {
    body += chunk;
    if (Buffer.byteLength(body) > maxBytes) {
      const error = new Error('Request body too large');
      error.statusCode = 413;
      throw error;
    }
  }
  try {
    return JSON.parse(body);
  } catch {
    const error = new Error('Invalid JSON body');
    error.statusCode = 400;
    throw error;
  }
}

function accountCookie(token, secure) {
  const parts = ['shiftlab_account=' + token, 'HttpOnly', 'SameSite=Lax', 'Path=/', 'Max-Age=' + PLAYER_SESSION_TTL_SECONDS];
  if (secure) parts.splice(2, 0, 'Secure');
  return parts.join('; ');
}

function authClientIp(req) {
  return req.headers['x-nf-client-connection-ip'] || req.socket.remoteAddress || 'unknown';
}

function pruneAttempts(attempts, now) {
  for (const [ip, entry] of attempts) {
    if (entry.resetAt <= now) attempts.delete(ip);
  }
}

async function createPlayerSession(accountId) {
  const token = randomBytes(32).toString('hex');
  const sessionHash = hashSessionToken(token);
  await db.execute(sql`delete from player_sessions where expires_at <= now()`);
  await db.execute(sql`
    insert into player_sessions (token_hash, player_id, expires_at)
    values (${sessionHash}, ${accountId}, now() + interval '30 days')
  `);
  return token;
}

async function establishPlayerSession(account, req, res) {
  const token = await createPlayerSession(account.id);
  res.setHeader('Set-Cookie', accountCookie(token, req.socket.encrypted || req.headers['x-forwarded-proto'] === 'https'));
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ authenticated: true, username: account.username }));
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const isSecureRequest = req.socket.encrypted || req.headers['x-forwarded-proto'] === 'https';
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Vary', 'Origin');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }

  if (url.pathname === '/api/account/signup' || url.pathname === '/api/account/login') {
    if (req.method !== 'POST') { res.writeHead(405); return res.end(); }
    if (req.headers['sec-fetch-site'] === 'cross-site') { res.writeHead(403); return res.end(); }
    if (!db) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: ACCOUNT_SERVICE_ERROR }));
    }

    let credentials;
    try { credentials = await readJsonBody(req, 4096); } catch (error) {
      res.writeHead(error.statusCode || 400, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: error.statusCode === 413 ? error.message : 'Invalid account request' }));
    }
    if (!credentials || typeof credentials.username !== 'string' || typeof credentials.password !== 'string' ||
        credentials.username.length > 64 || credentials.password.length > 128) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Enter a valid username and password' }));
    }
    const username = credentials.username.trim().toLowerCase();
    const signup = url.pathname.endsWith('/signup');
    if (!/^[a-z0-9_]{3,24}$/.test(username) || (signup && credentials.password.length < 8)) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: signup
        ? 'Use a 3–24 character username and a password with at least 8 characters'
        : 'Enter a valid username and password' }));
    }

    const now = Date.now();
    pruneAttempts(accountLoginAttempts, now);
    pruneAttempts(accountSignups, now);
    const ip = authClientIp(req);
    if (signup) {
      const attempt = accountSignups.get(ip);
      if (attempt && attempt.count >= 5) {
        res.writeHead(429, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Too many accounts created. Try again later.' }));
      }
      accountSignups.set(ip, attempt && attempt.resetAt > now
        ? { count: attempt.count + 1, resetAt: attempt.resetAt }
        : { count: 1, resetAt: now + 60 * 60 * 1000 });
    } else {
      const attempt = accountLoginAttempts.get(ip);
      if (attempt && attempt.count >= 5) {
        res.writeHead(429, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Too many sign-in attempts. Try again later.' }));
      }
    }

    try {
      let account;
      if (signup) {
        const salt = randomBytes(16).toString('hex');
        const passwordHash = (await scryptAsync(credentials.password, salt, 64)).toString('base64');
        const result = await db.execute(sql`
          insert into player_accounts (id, username, password_salt, password_hash)
          values (${randomUUID()}, ${username}, ${salt}, ${passwordHash})
          on conflict (username) do nothing
          returning id, username
        `);
        account = result.rows[0];
        if (!account) {
          res.writeHead(409, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'That username is already taken' }));
        }
      } else {
        const result = await db.execute(sql`
          select id, username, password_salt as salt, password_hash as password_hash
          from player_accounts where username = ${username}
        `);
        const stored = result.rows[0];
        const candidate = await scryptAsync(credentials.password, stored ? stored.salt : DUMMY_ACCOUNT_SALT, 64);
        const expected = stored ? Buffer.from(stored.password_hash, 'base64') : Buffer.alloc(64);
        const valid = !!stored && expected.length === candidate.length && timingSafeEqual(expected, candidate);
        if (!valid) {
          const current = accountLoginAttempts.get(ip);
          accountLoginAttempts.set(ip, current && current.resetAt > now
            ? { count: current.count + 1, resetAt: current.resetAt }
            : { count: 1, resetAt: now + 15 * 60 * 1000 });
          res.writeHead(401, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'Incorrect username or password' }));
        }
        accountLoginAttempts.delete(ip);
        account = stored;
      }
      await establishPlayerSession(account, req, res);
    } catch (error) {
      console.error('Player account request failed:', error);
      if (!res.headersSent) {
        res.writeHead(503, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: ACCOUNT_SERVICE_ERROR }));
      }
    }
    return;
  }

  if (url.pathname === '/api/account/status') {
    if (req.method !== 'GET') { res.writeHead(405); return res.end(); }
    if (!db) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: ACCOUNT_SERVICE_ERROR }));
    }
    try {
      const account = await playerFromCookie(req.headers.cookie);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(account
        ? { authenticated: true, username: account.username }
        : { authenticated: false }));
    } catch (error) {
      console.error('Player account status check failed:', error);
      res.writeHead(503, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: ACCOUNT_SERVICE_ERROR }));
    }
  }

  if (url.pathname === '/api/account/logout') {
    if (req.method !== 'POST') { res.writeHead(405); return res.end(); }
    if (req.headers['sec-fetch-site'] === 'cross-site') { res.writeHead(403); return res.end(); }
    const token = playerSessionFromCookie(req.headers.cookie);
    if (token && db) {
      try {
        const sessionHash = hashSessionToken(token);
        await db.execute(sql`delete from player_sessions where token_hash = ${sessionHash}`);
        for (const ws of wss.clients) {
          if (ws.playerSessionHash === sessionHash) ws.close(4002, 'Account signed out');
        }
      } catch (error) {
        console.error('Player account logout failed:', error);
        res.writeHead(503, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Could not sign out' }));
      }
    }
    const cookieParts = ['shiftlab_account=', 'HttpOnly', 'SameSite=Lax', 'Path=/', 'Max-Age=0'];
    if (req.socket.encrypted || req.headers['x-forwarded-proto'] === 'https') cookieParts.splice(2, 0, 'Secure');
    res.setHeader('Set-Cookie', cookieParts.join('; '));
    res.writeHead(204);
    return res.end();
  }

  if (url.pathname === '/api/admin/login') {
    if (req.method !== 'POST') { res.writeHead(405); return res.end(); }
    if (req.headers['sec-fetch-site'] === 'cross-site') { res.writeHead(403); return res.end(); }
    if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Admin sign-in is not configured' }));
    }

    let body = '';
    try {
      for await (const chunk of req) {
        body += chunk;
        if (Buffer.byteLength(body) > 2048) {
          res.writeHead(413);
          return res.end();
        }
      }
    } catch {
      res.writeHead(400);
      return res.end();
    }
    let credentials;
    try { credentials = JSON.parse(body); } catch {
      res.writeHead(400);
      return res.end();
    }
    if (!credentials || typeof credentials.username !== 'string' || credentials.username.length > 128 ||
        typeof credentials.password !== 'string' || credentials.password.length > 128) {
      res.writeHead(400);
      return res.end();
    }

    const now = Date.now();
    for (const [ip, attempt] of adminLoginAttempts) {
      if (attempt.resetAt <= now) adminLoginAttempts.delete(ip);
    }
    const ip = req.headers['x-nf-client-connection-ip'] || req.socket.remoteAddress || 'unknown';
    const attempt = adminLoginAttempts.get(ip);
    if (attempt && attempt.count >= 5 && attempt.resetAt > now) {
      res.writeHead(429, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Too many sign-in attempts. Try again later.' }));
    }
    const usernameMatches = safeCredentialMatch(credentials.username, ADMIN_USERNAME);
    const passwordMatches = safeCredentialMatch(credentials.password, ADMIN_PASSWORD);
    const valid = usernameMatches && passwordMatches;
    if (!valid) {
      const current = attempt && attempt.resetAt > now ? attempt : { count: 0, resetAt: now + 15 * 60 * 1000 };
      current.count++;
      adminLoginAttempts.set(ip, current);
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Incorrect username or password' }));
    }

    adminLoginAttempts.delete(ip);
    for (const [session, expiresAt] of adminSessions) {
      if (expiresAt <= now) adminSessions.delete(session);
    }
    const token = randomBytes(32).toString('hex');
    adminSessions.set(token, now + ADMIN_SESSION_TTL_MS);
    const cookieParts = ['shiftlab_admin=' + token, 'HttpOnly', 'SameSite=Strict', 'Path=/', 'Max-Age=43200'];
    if (isSecureRequest) cookieParts.splice(2, 0, 'Secure');
    res.setHeader('Set-Cookie', cookieParts.join('; '));
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ authenticated: true }));
  }

  if (url.pathname === '/api/admin/status') {
    if (req.method !== 'GET') { res.writeHead(405); return res.end(); }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ authenticated: !!adminSessionFromCookie(req.headers.cookie) }));
  }

  if (url.pathname === '/api/admin/logout') {
    if (req.method !== 'POST') { res.writeHead(405); return res.end(); }
    if (req.headers['sec-fetch-site'] === 'cross-site') { res.writeHead(403); return res.end(); }
    const token = adminSessionFromCookie(req.headers.cookie);
    if (token) adminSessions.delete(token);
    const cookieParts = ['shiftlab_admin=', 'HttpOnly', 'SameSite=Strict', 'Path=/', 'Max-Age=0'];
    if (isSecureRequest) cookieParts.splice(2, 0, 'Secure');
    res.setHeader('Set-Cookie', cookieParts.join('; '));
    res.writeHead(204);
    return res.end();
  }

  if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
    const filePath = resolve(PUBLIC_DIR, 'index.html');
    try {
      const html = await readFile(filePath, 'utf8');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(html);
    } catch (_) {
      res.writeHead(500); return res.end('Public site unavailable');
    }
  }

  if (url.pathname === '/api/session') {
    let id = (req.headers.cookie || '').match(/(?:^|; )shiftlab_player=([a-f0-9-]{36})(?:;|$)/)?.[1];
    if (!id) {
      id = randomUUID();
      const cookieParts = ['shiftlab_player=' + id, 'HttpOnly', 'SameSite=Lax', 'Path=/', 'Max-Age=31536000'];
      if (isSecureRequest) cookieParts.splice(2, 0, 'Secure');
      res.setHeader('Set-Cookie', cookieParts.join('; '));
    }
    res.writeHead(204); return res.end();
  }
  if (url.pathname === '/api/save') {
    const id = (req.headers.cookie || '').match(/(?:^|; )shiftlab_player=([a-f0-9-]{36})(?:;|$)/)?.[1];
    const namespace = url.searchParams.get('namespace');
    const key = url.searchParams.get('key');
    if (!id || !['economy', 'driftScores', 'mpProfile'].includes(namespace) || !/^[a-zA-Z0-9_]{1,50}$/.test(key || '')) {
      res.writeHead(400); return res.end('Invalid save request');
    }
    if (!db) {
      res.writeHead(503); return res.end('Save service unavailable');
    }
    try {
      const account = await playerFromCookie(req.headers.cookie);
      if (!account) {
        res.writeHead(401);
        return res.end('Sign in required');
      }
      if (req.method === 'GET') {
        const result = await db.execute(sql`select value from saves where player_id=${id} and namespace=${namespace} and key=${key}`);
        res.setHeader('Content-Type', 'application/json');
        return res.end(JSON.stringify(result.rows[0]?.value ?? null));
      }
      if (req.method === 'PUT') {
        if (req.headers['sec-fetch-site'] === 'cross-site') { res.writeHead(403); return res.end(); }
        let body = '';
        for await (const chunk of req) {
          body += chunk;
          if (body.length > 64000) { res.writeHead(413); return res.end(); }
        }
        const value = JSON.stringify(JSON.parse(body));
        await db.execute(sql`insert into saves (player_id, namespace, key, value) values (${id}, ${namespace}, ${key}, ${value}::jsonb) on conflict (player_id, namespace, key) do update set value=excluded.value`);
        res.writeHead(204); return res.end();
      }
      res.writeHead(405); return res.end();
    } catch (_) { res.writeHead(503); return res.end('Save service unavailable'); }
  }
  res.writeHead(404); res.end('Not found');
});

const wss = new WebSocketServer({
  server,
  path: "/ws",
  maxPayload: 16000,
  verifyClient(info, done) {
    if (!db) return done(false, 503, 'Account service unavailable');
    playerFromCookie(info.req.headers.cookie).then((account) => {
      if (!account) return done(false, 401, 'Sign in required');
      info.req.playerAccount = account;
      done(true);
    }).catch((error) => {
      console.error('WebSocket account verification failed:', error);
      done(false, 503, 'Account service unavailable');
    });
  }
});
const players = new Map(); // ws -> player
let nextPid = 1;

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  server.listen(PORT, HOST, () => {
    console.log(`ShiftLab server listening on http://${HOST}:${PORT}`);
  });
}

// Detect half-open connections (for example, a laptop losing Wi-Fi without a
// clean WebSocket close) so stale players do not remain in the room forever.
const heartbeat = setInterval(() => {
  for (const ws of wss.clients) {
    if (ws.isAlive === false) {
      ws.terminate();
      continue;
    }
    ws.isAlive = false;
    try { ws.ping(); } catch (_) { ws.terminate(); }
  }
}, HEARTBEAT_MS);
heartbeat.unref();
wss.on("close", () => clearInterval(heartbeat));

function cleanName(s) {
  s = String(s == null ? "" : s);
  let out = "";
  for (let i = 0; i < s.length && out.length < MAX_NAME; i++) {
    const c = s.charCodeAt(i);
    if (c >= 32 && c < 127 && c !== 124 && c !== 58) out += s[i];
  }
  return out || "Racer";
}

function cleanTrack(t) {
  t = String(t == null ? "" : t);
  return t === "drag" || t === "f1" ? t : "skid";
}

function clampInt(v, lo, hi) {
  v = Number(v);
  if (!Number.isFinite(v)) return lo;
  v = v | 0;
  return Math.max(lo, Math.min(hi, v));
}

function roster() {
  let s = "R";
  for (const p of players.values()) {
    s += "|" + p.pid + ":" + p.name + ":" + p.ci + ":" + (p.talk ? 1 : 0) + ":" + p.track;
  }
  return s;
}

function broadcast(message) {
  for (const ws of players.keys()) {
    if (ws.readyState === WebSocket.OPEN) ws.send(message);
  }
}

function sendToPid(pid, message) {
  for (const [ws, p] of players) {
    if (p.pid === pid && ws.readyState === WebSocket.OPEN) {
      ws.send(message);
      return true;
    }
  }
  return false;
}

function rateOK(p) {
  const now = Date.now();
  if (now - p.bucketT >= 1000) {
    p.bucketT = now;
    p.bucketN = 0;
  }
  p.bucketN++;
  return p.bucketN <= STATE_PER_SEC;
}

wss.on("connection", (ws, req) => {
  ws.adminSessionToken = adminSessionFromCookie(req.headers.cookie);
  ws.playerAccountId = req.playerAccount.id;
  ws.playerSessionHash = req.playerAccount.sessionHash;
  ws.isAlive = true;
  ws.on("pong", () => { ws.isAlive = true; });
  ws.send("Q");

  ws.on("message", (raw, isBinary) => {
    if (isBinary || ws.kicked) return;
    const data = raw.toString();
    if (!data || data.length > 16000) return;

    let p = players.get(ws);
    const tag = data.charCodeAt(0);

    if (tag === 67) { // C join
      if (p) return;
      if (players.size >= MAX_PLAYERS) {
        ws.send("F");
        return;
      }
      const parts = data.split("|");
      p = {
        pid: nextPid++,
        name: cleanName(parts[1]),
        ci: clampInt(parts[2], 0, 31),
        talk: false,
        track: cleanTrack(parts[3]),
        bucketT: Date.now(),
        bucketN: 0
      };
      players.set(ws, p);
      ws.send("I|" + p.pid);
      broadcast(roster());
      return;
    }

    if (!p) return;

    if (tag === 83) { // S state
      if (data.length > MAX_STATE_LEN || !rateOK(p)) return;
      broadcast("S|" + p.pid + "|" + data.slice(2));
      return;
    }

    if (tag === 80) { // P bring a player, using the existing client-side cheat panel
      if (!requireAdmin(ws)) return;
      if (!data.startsWith("P|") || data.length > 300 || !rateOK(p)) return;
      let dest;
      try { dest = JSON.parse(data.slice(2)); } catch { return; }
      if (!dest || !Number.isSafeInteger(dest.pid) || dest.pid <= 0 || dest.pid === p.pid ||
          !["skid", "drag", "f1"].includes(dest.track) || dest.track !== p.track ||
          ![dest.x, dest.y, dest.a].every(v => Number.isFinite(v) && Math.abs(v) <= 1e7)) return;
      const sent = sendToPid(dest.pid, "P|" + JSON.stringify({ track: dest.track, x: dest.x, y: dest.y, a: dest.a, name: p.name }));
      ws.send("P|" + JSON.stringify({ status: sent ? "ok" : "missing" }));
      return;
    }

    if (tag === 75) { // K kick from the existing client-side cheat panel
      if (!requireAdmin(ws)) return;
      if (!/^K\|[1-9][0-9]{0,9}$/.test(data)) return;
      const pid = Number(data.slice(2));
      if (!Number.isSafeInteger(pid) || pid === p.pid) return;
      for (const [target, info] of players) {
        if (info.pid !== pid || target.readyState !== WebSocket.OPEN) continue;
        target.kicked = true;
        players.delete(target);
        target.close(4001, "Kicked by admin");
        broadcast(roster());
        ws.send("K|ok|" + pid);
        return;
      }
      ws.send("K|missing|" + pid);
      return;
    }

    if (tag === 66) { // B room announcement (same client-side cheat panel as gifts)
      if (!requireAdmin(ws)) return;
      if (data.length > 282 || !data.startsWith("B|")) return;
      const now = Date.now();
      if (p.announcedAt && now - p.announcedAt < 3000) return;
      const text = data.slice(2).replace(/[\u0000-\u001f\u007f]/g, " ").trim();
      if (!text) return;
      p.announcedAt = now;
      broadcast("B|" + JSON.stringify({ name: p.name, text }));
      return;
    }

    if (tag === 78) { // N name
      p.name = cleanName(data.slice(2));
      broadcast(roster());
      return;
    }

    if (tag === 65) { // A talk
      const on = data.length > 2 && data[2] === "1";
      if (p.talk !== on) {
        p.talk = on;
        broadcast(roster());
      }
      return;
    }

    if (tag === 84) { // T track
      const t = cleanTrack(data.slice(2));
      if (p.track !== t) {
        p.track = t;
        broadcast(roster());
      }
      return;
    }

    if (tag === 86) { // V voice signalling
      if (data.length > MAX_VOICE_LEN) return;
      const i1 = data.indexOf("|");
      const i2 = data.indexOf("|", i1 + 1);
      if (i1 < 0 || i2 < 0) return;
      const to = Number(data.slice(i1 + 1, i2)) | 0;
      if (!to || to === p.pid) return;
      sendToPid(to, "V|" + p.pid + "|" + data.slice(i2 + 1));
      return;
    }

    if (tag === 71) { // G gift
      if (!requireAdmin(ws)) return;
      if (data.length > MAX_GIFT_LEN) return;
      const i1 = data.indexOf("|");
      const i2 = data.indexOf("|", i1 + 1);
      const i3 = data.indexOf("|", i2 + 1);
      if (i1 < 0 || i2 < 0 || i3 < 0) return;
      const to = Number(data.slice(i1 + 1, i2)) | 0;
      const kind = data.slice(i2 + 1, i3);
      const value = data.slice(i3 + 1);
      if (!to || (kind !== "cash" && kind !== "car")) return;
      sendToPid(to, "G|" + p.pid + "|" + p.name + "|" + kind + "|" + value);
      return;
    }
  });

  ws.on("close", () => {
    if (players.delete(ws)) broadcast(roster());
  });

  ws.on("error", () => {
    try { ws.close(); } catch (_) {}
  });
});

function requireAdmin(ws) {
  if (isAdminSession(ws.adminSessionToken)) return true;
  if (ws.readyState === WebSocket.OPEN) ws.send("X|Admin sign-in required.");
  return false;
}

export default server;
