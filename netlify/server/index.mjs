import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
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

wss.on("connection", (ws) => {
  ws.isAlive = true;
  ws.on("pong", () => { ws.isAlive = true; });
  ws.send("Q");

  ws.on("message", (raw, isBinary) => {
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

  });

  ws.on("close", () => {
    if (players.delete(ws)) broadcast(roster());
  });

  ws.on("error", () => {
    try { ws.close(); } catch (_) {}
  });
});

export default server;
