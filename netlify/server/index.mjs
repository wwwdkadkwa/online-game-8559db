import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { createHash, randomBytes, randomUUID, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import WebSocket, { WebSocketServer } from 'ws';
import { drizzle } from 'drizzle-orm/netlify-db';
import { sql } from 'drizzle-orm';
const HOST = process.env.HOST || '0.0.0.0';
const PUBLIC_DIR = resolve(fileURLToPath(new URL('../../public', import.meta.url)));
const PORT = Number(process.env.PORT || 8889);
const db = process.env.NETLIFY_DB_URL ? drizzle() : null;
const MAX_PLAYERS = 64;
const MAX_NAME = 14;
const MAX_STATE_LEN = 120;
const STATE_PER_SEC = 45;
const MAX_VOICE_LEN = 12000;
const HEARTBEAT_MS = 30000;
const ADMIN_SESSION_MS = 12 * 60 * 60 * 1000;
const ADMIN_LOGIN_WINDOW_MS = 15 * 60 * 1000;
const ADMIN_LOGIN_LIMIT = 8;
const MAX_ADMIN_ACCOUNTS = 10;
const scrypt = promisify(scryptCallback);

function sendJson(res, status, value) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(value));
}

function hashToken(token) {
  return createHash('sha256').update(token).digest('hex');
}

async function hashPassword(password, salt) {
  const result = await scrypt(password, salt, 64);
  return result.toString('hex');
}

async function verifyPassword(password, salt, expectedHash) {
  const actualHash = Buffer.from(await hashPassword(password, salt), 'hex');
  const expected = Buffer.from(expectedHash, 'hex');
  return actualHash.length === expected.length && timingSafeEqual(actualHash, expected);
}

async function readJsonBody(req, maxBytes = 4096) {
  let body = '';
  for await (const chunk of req) {
    body += chunk;
    if (Buffer.byteLength(body) > maxBytes) {
      const error = new Error('Request body is too large');
      error.statusCode = 413;
      throw error;
    }
  }
  try {
    const value = JSON.parse(body);
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error();
    return value;
  } catch {
    const error = new Error('Invalid JSON request');
    error.statusCode = 400;
    throw error;
  }
}

function configuredOwner() {
  const password = process.env.ADMIN_PASSWORD || '';
  if (password.length < 8 || password.length > 128) return null;
  return { password };
}

async function bootstrapOwner() {
  if (!db) throw new Error('Admin database is unavailable');
  const owner = configuredOwner();
  if (!owner) throw new Error('Owner credentials are not configured');
  const salt = randomBytes(16).toString('hex');
  const passwordHash = await hashPassword(owner.password, salt);
  const id = randomUUID();
  await db.execute(sql`
    insert into admin_users (id, username, password_salt, password_hash, role)
    values (${id}, 'owner', ${salt}, ${passwordHash}, 'owner')
    on conflict (username) do update set
      password_salt = excluded.password_salt,
      password_hash = excluded.password_hash,
      role = 'owner'
  `);
  const result = await db.execute(sql`
    select id, username, password_salt, password_hash, role from admin_users where username = 'owner'
  `);
  return result.rows[0] || null;
}

async function adminFromCookie(cookieHeader) {
  if (!db) return null;
  const token = (cookieHeader || '').match(/(?:^|; )shiftlab_admin=([a-f0-9]{64})(?:;|$)/)?.[1];
  if (!token) return null;
  const result = await db.execute(sql`
    select u.id, u.username, u.role, s.token_hash as "sessionTokenHash"
    from admin_sessions s
    join admin_users u on u.id = s.admin_id
    where s.token_hash = ${hashToken(token)} and s.expires_at > now()
  `);
  const admin = result.rows[0];
  return admin && (admin.role === 'owner' || admin.role === 'admin') ? admin : null;
}

async function recordAdminAction(admin, action, details = null) {
  const actor = admin.role === 'owner' ? 'Owner' : 'Admin ' + admin.id.slice(0, 8);
  await db.execute(sql`
    insert into admin_audit_logs (id, admin_id, username, action, details)
    values (${randomUUID()}, ${admin.id}, ${actor}, ${action},
      ${details === null ? null : JSON.stringify(details)}::jsonb)
  `);
}

async function readRequestAdmin(req, res, ownerOnly = false) {
  if (!db) {
    sendJson(res, 503, { error: 'Admin database is unavailable. Link a Netlify Database.' });
    return null;
  }
  let admin;
  try {
    admin = await adminFromCookie(req.headers.cookie);
  } catch (error) {
    console.error('Could not validate admin session:', error);
    sendJson(res, 503, { error: 'Could not validate the admin session.' });
    return null;
  }
  if (!admin) {
    sendJson(res, 401, { error: 'Enter the operator password to use admin controls.' });
    return null;
  }
  if (ownerOnly && admin.role !== 'owner') {
    sendJson(res, 403, { error: 'Owner access is required.' });
    return null;
  }
  return admin;
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

  if (url.pathname === '/api/admin/status' && req.method === 'GET') {
    let admin = null;
    if (db) {
      try {
        admin = await adminFromCookie(req.headers.cookie);
      } catch (error) {
        console.error('Could not load admin status:', error);
        return sendJson(res, 503, { error: 'Could not load admin status.' });
      }
    }
    return sendJson(res, 200, {
      available: Boolean(db),
      ownerConfigured: Boolean(configuredOwner()),
      authenticated: Boolean(admin),
      role: admin?.role || null
    });
  }

  if (url.pathname === '/api/admin/login' && req.method === 'POST') {
    if (req.headers['sec-fetch-site'] === 'cross-site') return sendJson(res, 403, { error: 'Cross-site requests are not allowed.' });
    if (!db) return sendJson(res, 503, { error: 'Admin database is unavailable. Link a Netlify Database.' });
    const owner = configuredOwner();
    if (!owner) return sendJson(res, 503, { error: 'Configure an 8–128 character ADMIN_PASSWORD on the server.' });
    const address = req.headers['x-nf-client-connection-ip'] || req.socket.remoteAddress || 'unknown';
    const addressHash = hashToken(String(address));
    let body;
    try {
      await db.execute(sql`delete from admin_login_attempts where reset_at <= now()`);
      const rate = await db.execute(sql`
        insert into admin_login_attempts (address_hash, attempts, reset_at)
        values (${addressHash}, 1, ${new Date(Date.now() + ADMIN_LOGIN_WINDOW_MS)})
        on conflict (address_hash) do update set
          attempts = case when admin_login_attempts.reset_at <= now() then 1 else admin_login_attempts.attempts + 1 end,
          reset_at = case when admin_login_attempts.reset_at <= now() then excluded.reset_at else admin_login_attempts.reset_at end
        returning attempts
      `);
      if (Number(rate.rows[0]?.attempts) > ADMIN_LOGIN_LIMIT) {
        return sendJson(res, 429, { error: 'Too many password attempts. Try again in 15 minutes.' });
      }
      body = await readJsonBody(req);
    } catch (error) {
      if (error.statusCode) return sendJson(res, error.statusCode, { error: error.message });
      console.error('Could not apply admin sign-in rate limit:', error);
      return sendJson(res, 503, { error: 'Could not process admin sign-in.' });
    }
    const password = typeof body.password === 'string' ? body.password : '';
    if (password.length < 8 || password.length > 128) {
      return sendJson(res, 400, { error: 'Enter a password between 8 and 128 characters.' });
    }
    try {
      let admin = null;
      if (password === owner.password) {
        const ownerAccount = await bootstrapOwner();
        if (ownerAccount && await verifyPassword(password, ownerAccount.password_salt, ownerAccount.password_hash)) {
          admin = ownerAccount;
        }
      }
      if (!admin) {
        const result = await db.execute(sql`
          select id, username, password_salt, password_hash, role
          from admin_users where role = 'admin' order by created_at asc
          limit ${MAX_ADMIN_ACCOUNTS}
        `);
        for (const candidate of result.rows) {
          if (await verifyPassword(password, candidate.password_salt, candidate.password_hash)) {
            admin = candidate;
            break;
          }
        }
      }
      if (!admin) {
        return sendJson(res, 401, { error: 'Incorrect operator password.' });
      }
      await db.execute(sql`delete from admin_login_attempts where address_hash = ${addressHash}`);
      const token = randomBytes(32).toString('hex');
      const tokenHash = hashToken(token);
      const expiresAt = new Date(Date.now() + ADMIN_SESSION_MS);
      await db.execute(sql`delete from admin_sessions where expires_at <= now()`);
      await db.execute(sql`
        insert into admin_sessions (token_hash, admin_id, expires_at)
        values (${tokenHash}, ${admin.id}, ${expiresAt})
      `);
      try {
        await recordAdminAction(admin, 'admin.login');
      } catch (error) {
        await db.execute(sql`delete from admin_sessions where token_hash = ${tokenHash}`);
        throw error;
      }
      const cookie = [
        `shiftlab_admin=${token}`, 'HttpOnly', 'SameSite=Strict', 'Path=/',
        `Max-Age=${Math.floor(ADMIN_SESSION_MS / 1000)}`
      ];
      if (isSecureRequest) cookie.splice(2, 0, 'Secure');
      res.setHeader('Set-Cookie', cookie.join('; '));
      return sendJson(res, 200, { role: admin.role });
    } catch (error) {
      console.error('Admin password check failed:', error);
      return sendJson(res, 503, { error: 'Admin access could not be unlocked.' });
    }
  }

  if (url.pathname === '/api/admin/logout' && req.method === 'POST') {
    res.setHeader('Set-Cookie', `shiftlab_admin=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${isSecureRequest ? '; Secure' : ''}`);
    if (req.headers['sec-fetch-site'] === 'cross-site') return sendJson(res, 403, { error: 'Cross-site requests are not allowed.' });
    if (!db) { res.writeHead(204); return res.end(); }
    try {
      const admin = await adminFromCookie(req.headers.cookie);
      if (admin) {
        await db.execute(sql`delete from admin_sessions where token_hash = ${admin.sessionTokenHash}`);
        await recordAdminAction(admin, 'admin.logout');
      }
      res.writeHead(204);
      return res.end();
    } catch (error) {
      console.error('Admin sign-out failed:', error);
      return sendJson(res, 503, { error: 'Could not lock the admin controls.' });
    }
  }

  if (url.pathname === '/api/admin/players' && req.method === 'GET') {
    const admin = await readRequestAdmin(req, res);
    if (!admin) return;
    return sendJson(res, 200, [...players.values()].map((player) => ({
      pid: player.pid, name: player.name, car: player.ci, track: player.track
    })));
  }

  if (url.pathname === '/api/admin/logs' && req.method === 'GET') {
    const admin = await readRequestAdmin(req, res, true);
    if (!admin) return;
    const limit = Math.max(1, Math.min(100, Number.parseInt(url.searchParams.get('limit') || '50', 10) || 50));
    try {
      const result = await db.execute(sql`
        select id, username, action, details, created_at as "createdAt"
        from admin_audit_logs order by created_at desc limit ${limit}
      `);
      return sendJson(res, 200, result.rows);
    } catch (error) {
      console.error('Could not load admin activity logs:', error);
      return sendJson(res, 503, { error: 'Could not load the activity log.' });
    }
  }

  if (url.pathname === '/api/admin/users' && req.method === 'GET') {
    const admin = await readRequestAdmin(req, res, true);
    if (!admin) return;
    try {
      const result = await db.execute(sql`
        select id, role, created_at as "createdAt"
        from admin_users order by created_at asc
      `);
      return sendJson(res, 200, result.rows);
    } catch (error) {
      console.error('Could not load admin users:', error);
      return sendJson(res, 503, { error: 'Could not load admin users.' });
    }
  }

  if (url.pathname === '/api/admin/users' && req.method === 'POST') {
    if (req.headers['sec-fetch-site'] === 'cross-site') return sendJson(res, 403, { error: 'Cross-site requests are not allowed.' });
    const admin = await readRequestAdmin(req, res, true);
    if (!admin) return;
    let body;
    try {
      body = await readJsonBody(req);
    } catch (error) {
      return sendJson(res, error.statusCode || 400, { error: error.message });
    }
    const password = typeof body.password === 'string' ? body.password : '';
    if (password.length < 8 || password.length > 128) {
      return sendJson(res, 400, { error: 'Use an 8–128 character admin password.' });
    }
    try {
      const count = await db.execute(sql`
        select count(*)::int as count from admin_users where role = 'admin'
      `);
      if (Number(count.rows[0]?.count) >= MAX_ADMIN_ACCOUNTS) {
        return sendJson(res, 409, { error: 'The maximum number of admin passwords has been reached.' });
      }
      const existing = await db.execute(sql`
        select password_salt, password_hash from admin_users
      `);
      for (const account of existing.rows) {
        if (await verifyPassword(password, account.password_salt, account.password_hash)) {
          return sendJson(res, 409, { error: 'That password is already assigned to an admin.' });
        }
      }
      const salt = randomBytes(16).toString('hex');
      const passwordHash = await hashPassword(password, salt);
      const id = randomUUID();
      const username = 'admin_' + id;
      const result = await db.execute(sql`
        insert into admin_users (id, username, password_salt, password_hash, role, created_by)
        values (${id}, ${username}, ${salt}, ${passwordHash}, 'admin', ${admin.id})
        on conflict (username) do nothing
        returning id, role, created_at as "createdAt"
      `);
      if (!result.rows[0]) return sendJson(res, 409, { error: 'Could not create the admin password.' });
      try {
        await recordAdminAction(admin, 'admin.created', { accountId: id });
      } catch (error) {
        try {
          await db.execute(sql`delete from admin_users where id = ${id}`);
        } catch (cleanupError) {
          console.error('Could not roll back an unlogged admin account:', cleanupError);
        }
        throw error;
      }
      return sendJson(res, 201, result.rows[0]);
    } catch (error) {
      console.error('Could not create admin user:', error);
      return sendJson(res, 503, { error: 'Could not create the admin user or record the activity.' });
    }
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
  maxPayload: 16000
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

async function socketAdmin(ws) {
  const initialAdmin = await ws.adminSessionPromise;
  const admin = initialAdmin ? await adminFromCookie(ws.adminCookieHeader) : null;
  if (!admin && ws.readyState === WebSocket.OPEN) ws.send('X|Admin sign-in is required for that action.');
  return admin;
}

wss.on("connection", (ws, req) => {
  ws.isAlive = true;
  ws.on("pong", () => { ws.isAlive = true; });
  ws.adminCookieHeader = req.headers.cookie || '';
  ws.adminSessionPromise = /(?:^|; )shiftlab_admin=[a-f0-9]{64}(?:;|$)/.test(ws.adminCookieHeader)
    ? adminFromCookie(ws.adminCookieHeader).catch((error) => {
      console.error('Could not validate WebSocket admin session:', error);
      return null;
    })
    : Promise.resolve(null);
  ws.send("Q");

  ws.on("message", async (raw, isBinary) => {
    try {
    if (isBinary) return;
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

    if (tag === 75) { // K kick
      const admin = await socketAdmin(ws);
      if (!admin) return;
      if (Date.now() - (p.adminActionAt || 0) < 1000) {
        ws.send('X|Wait a moment before using another admin action.');
        return;
      }
      p.adminActionAt = Date.now();
      const targetPid = Number(data.slice(2));
      if (!Number.isInteger(targetPid) || targetPid <= 0 || targetPid === p.pid) {
        ws.send('X|Choose another online player.');
        return;
      }
      const target = [...players.entries()].find(([, player]) => player.pid === targetPid);
      if (!target) {
        ws.send('X|That player is no longer online.');
        return;
      }
      await recordAdminAction(admin, 'player.kicked', { pid: targetPid, name: target[1].name });
      players.delete(target[0]);
      try { target[0].close(4001, 'Removed by an administrator'); } catch (_) {}
      broadcast(roster());
      ws.send('X|Player removed from the room.');
      return;
    }

    if (tag === 66) { // B broadcast
      const admin = await socketAdmin(ws);
      if (!admin) return;
      if (Date.now() - (p.adminActionAt || 0) < 1000) {
        ws.send('X|Wait a moment before using another admin action.');
        return;
      }
      p.adminActionAt = Date.now();
      const message = data.slice(2).replace(/[|\r\n]/g, ' ').replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, 240);
      if (!message) {
        ws.send('X|Enter an announcement first.');
        return;
      }
      await recordAdminAction(admin, 'announcement.sent', { message });
      broadcast('B|' + message);
      ws.send('X|Announcement sent.');
      return;
    }

    if (tag === 83) { // S state
      if (data.length > MAX_STATE_LEN || !rateOK(p)) return;
      broadcast("S|" + p.pid + "|" + data.slice(2));
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

    } catch (error) {
      console.error('WebSocket message could not be processed:', error);
      if (ws.readyState === WebSocket.OPEN) ws.send('X|The server could not complete that request.');
    }
  });

  ws.on("close", () => {
    if (players.delete(ws)) broadcast(roster());
  });

  ws.on("error", () => {
    try { ws.close(); } catch (_) {}
  });
});

export default server;
