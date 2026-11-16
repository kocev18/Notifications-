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
    if (!t.notify || t.done || !t.date) continue;
    const tm = t.time || '09:00';
    const key = t.id + '|' + t.date + ' ' + tm;
    if (sent[key]) continue;
    const late = minutesBetween(now, t.date + ' ' + tm);
    if (late < -1 || late > 90) continue; // 1 минута по-рано, за да дойде точно в часа
    const em = t.prio === 3 ? '🔴' : t.prio === 2 ? '🟡' : '🟢';
    const r = await sendPush(env, sub, { title: '📋 Задачи', body: em + ' ' + tm + ' · ' + t.title, tag: t.id, url: './?t=' + encodeURIComponent(t.id) });
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
  const farm = state.farm || {};
  rules.push({ id: 'eggs', at: '19:00', on: !(farm.days && farm.days[date]), body: '🟡 19:00 · Яребична кокошки – запиши яйцата за днес' });
  (farm.vacc || []).forEach((v) => {
    if (v.done || !v.date) return;
    if (v.date === date) rules.push({ id: 'vac-' + v.id, at: '09:00', on: true, body: '🟡 09:00 · Днес: ' + v.title });
    const tom = new Date(Date.UTC(yy, mm - 1, dd + 1)).toISOString().slice(0, 10);
    if (v.date === tom) rules.push({ id: 'vac1-' + v.id, at: '09:00', on: true, body: '🟡 09:00 · Утре: ' + v.title });
  });
  for (const r of rules) {
    const key = 'rule:' + r.id + '|' + date;
    if (!r.on || sent[key]) continue;
    const late = minutesBetween(now, date + ' ' + r.at);
    if (late < -1 || late > 90) continue; // 1 минута по-рано, за да дойде точно в часа
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


// ---------- Хора: входящи съобщения и възлагане ----------
const okCode = (c) => typeof c === 'string' && /^[a-z0-9]{6,20}$/.test(c);
const kvJson = async (env, k, d) => { const r = await env.KV.get(k); return r ? JSON.parse(r) : d; };
async function pushOwner(env, payload) {
  const raw = await env.KV.get('sub'); if (!raw) return null;
  const r = await sendPush(env, JSON.parse(raw), payload);
  if (r.status === 404 || r.status === 410) await env.KV.delete('sub');
  return r.status;
}
async function personByCode(env, code) {
  if (!okCode(code)) return null;
  const people = await kvJson(env, 'people', {});
  return people[code] || null;
}

async function publicRoute(req, env, url) {
  const p = url.pathname;
  if (p === '/hi' && req.method === 'GET') {
    const who = await personByCode(env, url.searchParams.get('k'));
    return who ? json({ name: who.name }) : json({ error: 'unknown' }, 404);
  }
  if (p === '/in' && req.method === 'POST') {
    const b = await req.json(); const who = await personByCode(env, b.code);
    if (!who) return json({ error: 'unknown' }, 404);
    const text = String(b.text || '').trim().slice(0, 500);
    if (!text) return json({ error: 'empty' }, 400);
    const inbox = await kvJson(env, 'inbox', []);
    if (inbox.filter((x) => x.pid === who.id).length >= 30) return json({ error: 'too many' }, 429);
    inbox.push({ id: crypto.randomUUID().slice(0, 8), pid: who.id, name: who.name, text, at: Date.now() });
    await env.KV.put('inbox', JSON.stringify(inbox.slice(-100)));
    await pushOwner(env, { title: '📥 ' + who.name, body: text, tag: 'in-' + who.id, url: './?inbox=1' });
    return json({ ok: true });
  }
  if (p === '/mine' && req.method === 'GET') {
    const who = await personByCode(env, url.searchParams.get('k'));
    if (!who) return json({ error: 'unknown' }, 404);
    const assigned = (await kvJson(env, 'assigned', [])).filter((x) => x.pid === who.id).slice(-30).reverse();
    return json({ name: who.name, tasks: assigned.map((x) => ({ id: x.id, title: x.title, at: x.at, done: !!x.done })) });
  }
  if (p === '/mine/done' && req.method === 'POST') {
    const b = await req.json(); const who = await personByCode(env, b.code);
    if (!who) return json({ error: 'unknown' }, 404);
    const assigned = await kvJson(env, 'assigned', []);
    const t = assigned.find((x) => x.id === b.id && x.pid === who.id);
    if (!t) return json({ error: 'no task' }, 404);
    t.done = b.done === false ? false : true; t.doneAt = Date.now();
    await env.KV.put('assigned', JSON.stringify(assigned));
    if (t.done) await pushOwner(env, { title: '✅ ' + who.name, body: 'Готово: ' + t.title, tag: 'done-' + t.id, url: './' });
    return json({ ok: true });
  }
  if (p === '/psub' && req.method === 'POST') {
    const b = await req.json(); const who = await personByCode(env, b.code);
    if (!who || !b.sub || !b.sub.endpoint) return json({ error: 'bad' }, 400);
    const subs = await kvJson(env, 'psubs', {}); subs[who.id] = b.sub;
    await env.KV.put('psubs', JSON.stringify(subs));
    await sendPush(env, b.sub, { title: '📋 Задачи', body: '🟢 Известията са включени, ' + who.name, url: './p.html?k=' + b.code });
    return json({ ok: true });
  }
  return null;
}

async function ownerRoute(req, env, url) {
  const p = url.pathname;
  if (p === '/people' && req.method === 'PUT') {
    const b = await req.json(); const clean = {};
    Object.keys(b.people || {}).forEach((c) => { if (okCode(c) && b.people[c] && b.people[c].id) clean[c] = { id: String(b.people[c].id), name: String(b.people[c].name || '').slice(0, 60) }; });
    await env.KV.put('people', JSON.stringify(clean));
    return json({ ok: true, n: Object.keys(clean).length });
  }
  if (p === '/inbox' && req.method === 'GET') return json({ items: await kvJson(env, 'inbox', []) });
  if (p === '/inbox/ack' && req.method === 'POST') {
    const b = await req.json(); const ids = new Set(b.ids || []);
    const inbox = (await kvJson(env, 'inbox', [])).filter((x) => !ids.has(x.id));
    await env.KV.put('inbox', JSON.stringify(inbox));
    return json({ ok: true });
  }
  if (p === '/assign' && req.method === 'POST') {
    const b = await req.json(); const title = String(b.title || '').trim().slice(0, 300);
    if (!b.pid || !title) return json({ error: 'bad' }, 400);
    const assigned = await kvJson(env, 'assigned', []);
    const t = { id: crypto.randomUUID().slice(0, 8), pid: String(b.pid), title, at: Date.now(), done: false };
    assigned.push(t); await env.KV.put('assigned', JSON.stringify(assigned.slice(-200)));
    const subs = await kvJson(env, 'psubs', {}); const people = await kvJson(env, 'people', {});
    const code = Object.keys(people).find((c) => people[c].id === t.pid);
    let pushed = false;
    if (subs[t.pid] && code) {
      const r = await sendPush(env, subs[t.pid], { title: '📋 Задача от Сашо', body: title, tag: 'as-' + t.id, url: './p.html?k=' + code });
      pushed = r.status < 300;
      if (r.status === 404 || r.status === 410) { delete subs[t.pid]; await env.KV.put('psubs', JSON.stringify(subs)); }
    }
    return json({ ok: true, id: t.id, pushed, code: code || null });
  }
  if (p === '/assigned' && req.method === 'GET') return json({ items: (await kvJson(env, 'assigned', [])).slice(-60) });
  return null;
}


// ---------- Профили (вход с име и парола) ----------
const okUser = (u) => typeof u === 'string' && /^[\p{L}\p{N}_.-]{2,32}$/u.test(u);
async function pbkdf(pass, saltB64) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: b64u.dec(saltB64), iterations: 100000 }, key, 256);
  return b64u.enc(new Uint8Array(bits));
}
async function hmacTok(env, msg) {
  const k = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.TOKEN), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64u.enc(new Uint8Array(await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(msg))));
}
const sameStr = (a, b) => { if (a.length !== b.length) return false; let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0; };
async function authLevel(req, env) {
  const h = req.headers.get('Authorization') || '';
  if (!h.startsWith('Bearer ')) return null;
  const t = h.slice(7);
  if (sameStr(t, env.TOKEN)) return 'master';
  const m = /^u\.([^.]+)\.([A-Za-z0-9_-]+)$/.exec(t);
  if (!m) return null;
  const u = decodeURIComponent(m[1]); const acc = (await kvJson(env, 'accounts', {}))[u];
  if (!acc) return null;
  return sameStr(m[2], await hmacTok(env, 'sess|' + u + '|' + acc.salt)) ? 'user' : null;
}
async function loginRoute(req, env, url) {
  if (url.pathname !== '/login' || req.method !== 'POST') return null;
  const b = await req.json().catch(() => ({})); const u = String(b.u || '').trim(); const p = String(b.p || '');
  const key = 'try:' + u.toLowerCase(); const tries = +(await env.KV.get(key) || 0);
  if (tries >= 10) return json({ error: 'locked' }, 429);
  const accounts = await kvJson(env, 'accounts', {});
  const name = Object.keys(accounts).find((x) => x.toLowerCase() === u.toLowerCase());
  const acc = name && accounts[name];
  if (!acc || !sameStr(await pbkdf(p, acc.salt), acc.hash)) {
    await env.KV.put(key, String(tries + 1), { expirationTtl: 900 });
    return json({ error: 'bad' }, 401);
  }
  await env.KV.delete(key);
  return json({ token: 'u.' + encodeURIComponent(name) + '.' + await hmacTok(env, 'sess|' + name + '|' + acc.salt), name });
}
async function accountRoute(req, env, url) {
  const p = url.pathname;
  if (p === '/accounts' && req.method === 'GET') return json({ names: Object.keys(await kvJson(env, 'accounts', {})) });
  if (p === '/account' && req.method === 'POST') {
    const b = await req.json(); const u = String(b.u || '').trim(); const pw = String(b.p || '');
    if (!okUser(u) || pw.length < 6) return json({ error: 'bad' }, 400);
    const accounts = await kvJson(env, 'accounts', {});
    const old = Object.keys(accounts).find((x) => x.toLowerCase() === u.toLowerCase()); if (old) delete accounts[old];
    const salt = b64u.enc(crypto.getRandomValues(new Uint8Array(16)));
    accounts[u] = { salt, hash: await pbkdf(pw, salt) };
    await env.KV.put('accounts', JSON.stringify(accounts));
    return json({ ok: true });
  }
  if (p === '/account/del' && req.method === 'POST') {
    const b = await req.json(); const accounts = await kvJson(env, 'accounts', {}); delete accounts[b.u];
    await env.KV.put('accounts', JSON.stringify(accounts));
    return json({ ok: true });
  }
  return null;
}

export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { headers: CORS });
    const url = new URL(req.url);
    const pub = await publicRoute(req, env, url);
    if (pub) return pub;
    const lg = await loginRoute(req, env, url); if (lg) return lg;
    const lvl = await authLevel(req, env);
    if (!lvl) return json({ error: 'unauthorized' }, 401);
    if (lvl === 'master') { const ac = await accountRoute(req, env, url); if (ac) return ac; }
    const own = await ownerRoute(req, env, url);
    if (own) return own;
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
    if (url.pathname === '/assist' && req.method === 'POST') {
      if (!env.AI) return json({ error: 'no ai' }, 501);
      const b = await req.json();
      const text = String(b.text || '').slice(0, 1500);
      const list = (b.tasks || []).slice(0, 80).map((t) => [t.id, t.title, t.date ? t.date + ' (' + ['неделя','понеделник','вторник','сряда','четвъртък','петък','събота'][new Date(t.date + 'T12:00:00Z').getUTCDay()] + ')' : '-', t.time || '-', t.done ? 'готова' : 'отворена'].join(' | ')).join('\n');
      const WDN = ['неделя','понеделник','вторник','сряда','четвъртък','петък','събота'];
      const base = new Date(String(b.today) + 'T12:00:00Z'); const cal = [];
      for (let i = 0; i < 14; i++) { const d = new Date(base.getTime() + i * 86400000); cal.push((i === 0 ? 'днес' : i === 1 ? 'утре' : i === 2 ? 'вдругиден' : '') + ' ' + WDN[d.getUTCDay()] + ' = ' + d.toISOString().slice(0, 10)); }
      const lastIds = Array.isArray(b.last) ? b.last.slice(0, 6).map(String) : [];
      const hist = (b.hist || []).slice(-6).map((m) => (m.r === 'u' ? 'Потребител: ' : 'Асистент: ') + String(m.t).slice(0, 300)).join('\n');
      const sys = 'Ти си асистент в приложение за задачи. Потребителят говори на български. Днес е ' + b.today + ' (' + b.weekday + '), часът е ' + b.now + '.\n' +
        'Отговори САМО с един JSON обект без друг текст: {"reply":"кратък отговор на български","actions":[...]}.\n' +
        'Действия: {"op":"add","title":"...","date":"YYYY-MM-DD или празно","time":"HH:MM или празно","prio":1|2|3} ; {"op":"done","id":"..."} ; {"op":"delete","id":"..."} ; {"op":"edit","id":"...","title":"по избор","date":"YYYY-MM-DD по избор","time":"HH:MM по избор","prio":1|2|3 по избор} — променя САМО подадените полета (напр. „смени я за 13:00“ е само time; „премести за петък“ е само date) ; {"op":"copy","id":"...","date":"YYYY-MM-DD","time":"HH:MM по избор, иначе се взима от оригинала"} — копира задача за друг ден (за няколко дни — няколко copy действия).\n' +
        'КАЛЕНДАР (ползвай САМО него за дати): ' + cal.join('; ') + '. За по-далечни дати смятай от календара. Приоритет: 3 = висок/важен/спешен, 2 = среден, 1 = нисък. ' + (lastIds.length ? 'Последно създадени/променени от теб задачи (id): ' + lastIds.join(', ') + ' — когато потребителят каже „задачата“, „нея“, „тази“ без име, става дума за тях. ' : '') + (hist ? 'Скорошен разговор:\n' + hist + '\n' : '') + 'Ако задачата не е ясна (няколко възможни и няма контекст), попитай в reply коя има предвид, с actions []. '+
        'Правила: Използвай id само от списъка. Когато той казва „задачата от вторник“, намери я по датата/деня и заглавието в списъка; ако са няколко, вземи тези, които пасват най-добре. Ако потребителят само пита (какво имам утре, колко…), actions е [] и отговаряш в reply по списъка. Не измисляй задачи, които не са поискани. Заглавието да е кратко, без думите за дата и час.\n' +
        'Текущи задачи (id | заглавие | дата | час | статус):\n' + (list || '(няма)');
      const msgs = [{ role: 'system', content: sys }, { role: 'user', content: text }];
      let r;
      try { r = await env.AI.run('@cf/meta/llama-3.3-70b-instruct-fp8-fast', { messages: msgs, max_tokens: 900 }); }
      catch (e) { try { r = await env.AI.run('@cf/meta/llama-3.1-8b-instruct', { messages: msgs, max_tokens: 900 }); } catch (e2) { return json({ error: String(e2 && e2.message || e2) }, 502); } }
      const raw = typeof r.response === 'string' ? r.response : JSON.stringify(r.response || {});
      let out = null;
      try { const m = raw.match(/\{[\s\S]*\}/); out = JSON.parse(m ? m[0] : raw); } catch (e) {}
      if (!out || typeof out !== 'object') return json({ reply: raw.slice(0, 400) || 'Не разбрах, опитай по друг начин.', actions: [] });
      return json({ reply: String(out.reply || ''), actions: Array.isArray(out.actions) ? out.actions.slice(0, 12) : [] });
    }
    if (url.pathname === '/ai' && req.method === 'POST') {
      if (!env.AI) return json({ error: 'no ai' }, 501);
      const b = await req.json();
      const msgs = [{ role: 'system', content: 'Отговаряй само с исканото съдържание, без обяснения и без увод.' }, { role: 'user', content: String(b.prompt || '').slice(0, 12000) }];
      let r;
      try { r = await env.AI.run('@cf/meta/llama-3.3-70b-instruct-fp8-fast', { messages: msgs, max_tokens: 1800 }); }
      catch (e) { try { r = await env.AI.run('@cf/meta/llama-3.1-8b-instruct', { messages: msgs, max_tokens: 1800 }); } catch (e2) { return json({ error: String(e2 && e2.message || e2) }, 502); } }
      return json({ text: String(r.response || '') });
    }
    return json({ error: 'not found' }, 404);
  },
  async scheduled(ev, env, ctx) { ctx.waitUntil(runDue(env)); },
};
