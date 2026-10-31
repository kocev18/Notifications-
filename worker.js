// Задачи — сървър за известия и синхронизация (Cloudflare Worker, безплатен план)
// Нужни: KV свързване с име KV; тайни: TOKEN, VAPID_PRIVATE, VAPID_SUBJECT; Cron Trigger: * * * * *
const VAPID_PUBLIC = 'BM79tK549nXqcAxRszfTvkTleUBpAv_0zkT9QqrKXjJVCRucZ1MjCMtJSXTf_Xa87XVu1Awv7cxyKH9W7ygB8TU';
const TZ = 'Europe/Sofia';

const b64u = {
  enc: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
  dec: (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0)),
};
const te = new TextEncoder();
const concat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let p = 0; for (const x of a) { o.set(x, p); p += x.length; } return o; };

async function hkdf(salt, ikm, info, len) {
  const k = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, k, len * 8));
}

async function vapidJwt(env, endpoint) {
  const pub = b64u.dec(VAPID_PUBLIC);
  const jwk = { kty: 'EC', crv: 'P-256', d: env.VAPID_PRIVATE, x: b64u.enc(pub.slice(1, 33)), y: b64u.enc(pub.slice(33, 65)) };
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const head = b64u.enc(te.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const body = b64u.enc(te.encode(JSON.stringify({ aud: new URL(endpoint).origin, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: env.VAPID_SUBJECT })));
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, te.encode(head + '.' + body));
  return head + '.' + body + '.' + b64u.enc(sig);
}

async function encryptPayload(sub, text) {
  const ua = b64u.dec(sub.keys.p256dh), auth = b64u.dec(sub.keys.auth);
  const eph = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPub = new Uint8Array(await crypto.subtle.exportKey('raw', eph.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', ua, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, eph.privateKey, 256));
  const prk = await hkdf(auth, shared, concat(te.encode('WebPush: info\0'), ua, asPub), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, prk, te.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(salt, prk, te.encode('Content-Encoding: nonce\0'), 12);
  const aes = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aes, concat(te.encode(text), new Uint8Array([2]))));
  return concat(salt, new Uint8Array([0, 0, 16, 0, 65]), asPub, ct);
}

async function sendPush(env, sub, payload) {
  const body = await encryptPayload(sub, JSON.stringify(payload));
  const jwt = await vapidJwt(env, sub.endpoint);
  const res = await fetch(sub.endpoint, {
    method: 'POST',
    headers: { 'Content-Encoding': 'aes128gcm', 'Content-Type': 'application/octet-stream', TTL: '86400', Urgency: 'high', Authorization: 'vapid t=' + jwt + ', k=' + VAPID_PUBLIC },
    body,
  });
  return { status: res.status, text: res.status >= 300 ? await res.text() : '' };
}

function nowSofia() {
  const p = Object.fromEntries(new Intl.DateTimeFormat('en-CA', { timeZone: TZ, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }).formatToParts(new Date()).map((x) => [x.type, x.value]));
  return p.year + '-' + p.month + '-' + p.day + ' ' + p.hour + ':' + p.minute;
}
const minutesBetween = (a, b) => (Date.parse(a.replace(' ', 'T') + ':00Z') - Date.parse(b.replace(' ', 'T') + ':00Z')) / 60000;

const yday = (d) => { const [y, m, dd] = d.split('-').map(Number); return new Date(Date.UTC(y, m - 1, dd - 1)).toISOString().slice(0, 10); };
const spTxt = (st, d) => { const a = (st.spend && st.spend[d]) || []; const t = a.reduce((s, x) => s + x.amt, 0); return a.length ? ' (вече: ' + t.toFixed(2) + ' лв)' : ''; };

async function runDue(env) {
  const [stRaw, subRaw, sentRaw] = await Promise.all([env.KV.get('state'), env.KV.get('sub'), env.KV.get('sent')]);
  if (!stRaw || !subRaw) return { sent: 0 };
  const state = JSON.parse(stRaw).state || {}, sub = JSON.parse(subRaw), sent = sentRaw ? JSON.parse(sentRaw) : {};
  const now = nowSofia(); let n = 0, changed = false;
  for (const t of state.tasks || []) {
    if (!t.notify || t.done || !t.date || !t.time) continue;
    const key = t.id + '|' + t.date + ' ' + t.time;
    if (sent[key]) continue;
    const late = minutesBetween(now, t.date + ' ' + t.time);
    if (late < 0 || late > 90) continue;
    const em = t.prio === 3 ? '🔴' : t.prio === 2 ? '🟡' : '🟢';
    const r = await sendPush(env, sub, { title: '📋 Задачи', body: em + ' ' + t.time + ' · ' + t.title, tag: t.id, url: './?t=' + encodeURIComponent(t.id) });
    if (r.status === 404 || r.status === 410) { await env.KV.delete('sub'); break; }
    if (r.status < 300) { sent[key] = Date.now(); n++; changed = true; }
  }
  // Редовни напомняния (вместо тези от Reminders)
  const date = now.slice(0, 10), hhmm = now.slice(11), [yy, mm, dd] = date.split('-').map(Number);
  const dow = new Date(Date.UTC(yy, mm - 1, dd)).getUTCDay(), lastFeb = new Date(Date.UTC(yy, 2, 0)).getUTCDate();
  const hoursDone = (state.hours && state.hours[date]) || (state.hdone && state.hdone[date]);
  const rules = [
    { id: 'hours', at: '22:00', on: !hoursDone, body: '🟡 22:00 · Часове Ред Хот – въведи часовете за днес' },
    { id: 'oil', at: '10:00', on: dow === 1, body: '🟡 10:00 · Проверка масло и антифриз' },
    { id: 'sched', at: '10:00', on: dow === 0, body: '🟡 10:00 · График – напиши графика във Viber групите' },
    { id: 'sp8', at: '08:00', on: true, body: '🟡 08:00 · Разходи – запиши колко похарчи вчера' + spTxt(state, yday(date)) },
    { id: 'sp22', at: '22:00', on: true, body: '🟡 22:00 · Разходи – запиши колко похарчи днес' + spTxt(state, date) },
    { id: 'andrea', at: '10:00', on: dd === 30 || (mm === 2 && dd === lastFeb), body: '🟡 10:00 · Честити на Андреа' },
  ];
  for (const r of rules) {
    const key = 'rule:' + r.id + '|' + date;
    if (!r.on || sent[key]) continue;
    const late = minutesBetween(now, date + ' ' + r.at);
    if (late < 0 || late > 90) continue;
    const x = await sendPush(env, sub, { title: '📋 Задачи', body: r.body, tag: 'rule-' + r.id, url: './' });
    if (x.status === 404 || x.status === 410) { await env.KV.delete('sub'); break; }
    if (x.status < 300) { sent[key] = Date.now(); n++; changed = true; }
  }
  for (const k of Object.keys(sent)) if (Date.now() - sent[k] > 7 * 86400000) { delete sent[k]; changed = true; }
  if (changed) await env.KV.put('sent', JSON.stringify(sent));
  return { sent: n };
}

const CORS = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Authorization, Content-Type', 'Access-Control-Allow-Methods': 'GET, PUT, POST, OPTIONS' };
const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { ...CORS, 'Content-Type': 'application/json' } });

export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { headers: CORS });
    const url = new URL(req.url);
    if (req.headers.get('Authorization') !== 'Bearer ' + env.TOKEN) return json({ error: 'unauthorized' }, 401);
    if (url.pathname === '/state' && req.method === 'GET') {
      const raw = await env.KV.get('state');
      return json(raw ? JSON.parse(raw) : { rev: 0, state: null });
    }
    if (url.pathname === '/state' && req.method === 'PUT') {
      const b = await req.json(); const rev = Date.now();
      await env.KV.put('state', JSON.stringify({ rev, state: b.state }));
      return json({ rev });
    }
    if (url.pathname === '/sub' && req.method === 'POST') {
      await env.KV.put('sub', JSON.stringify(await req.json()));
      return json({ ok: true });
    }
    if (url.pathname === '/test' && req.method === 'POST') {
      const raw = await env.KV.get('sub'); if (!raw) return json({ error: 'no subscription' }, 400);
      const r = await sendPush(env, JSON.parse(raw), { title: '📋 Задачи', body: '🟢 Тест: известията работят', url: './' });
      return json(r, r.status < 300 ? 200 : 502);
    }
    return json({ error: 'not found' }, 404);
  },
  async scheduled(ev, env, ctx) { ctx.waitUntil(runDue(env)); },
};
