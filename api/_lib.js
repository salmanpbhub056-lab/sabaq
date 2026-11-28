// Shared helpers for Sabaq serverless functions (files starting with _ are not public routes).
const crypto = require('crypto');
const env = () => ({ SB: process.env.SUPABASE_URL, KEY: process.env.SUPABASE_SERVICE_KEY, SEC: process.env.ADMIN_SECRET });
const eq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const hmac = p => crypto.createHmac('sha256', env().SEC).update(p).digest('base64url');
const q = v => encodeURIComponent(v);

async function db(method, table, query, body, prefer) {
  const { SB, KEY } = env();
  const r = await fetch(`${SB}/rest/v1/${table}${query ? '?' + query : ''}`, {
    method,
    headers: { apikey: KEY, Authorization: 'Bearer ' + KEY, 'Content-Type': 'application/json', Prefer: prefer || 'return=representation' },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  const t = await r.text();
  if (!r.ok) throw new Error(r.status + ' ' + t.slice(0, 300));
  return t ? JSON.parse(t) : [];
}
const sel = (t, query) => db('GET', t, query);
const ins = (t, row) => db('POST', t, '', row);
const upd = (t, query, patch) => db('PATCH', t, query, patch);
const del = (t, query) => db('DELETE', t, query, undefined, 'return=minimal');

const fail = (m, c) => { const e = new Error(m); e.user = 1; e.code = c || 400; throw e; };
const str = (v, max, min = 1) => { v = String(v ?? '').trim(); if (v.length < min || v.length > max) fail(`Please enter ${min}-${max} characters.`); return v; };

const BAD = /\b(fuck|shit|bitch|bastard|asshole|idiot|stupid)\b/i, URLR = /(https?:\/\/|www\.|\.com\b|\.pk\b)/i, PHR = /(\+?92|0)?3\d{2}[ -]?\d{7}/;
const modr = t => BAD.test(t) ? 'Please keep it respectful.' : URLR.test(t) ? 'Links are not allowed.' : PHR.test(t) ? 'Please do not share phone numbers in public text.' : '';

const cookie = (req, n) => { const c = (req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith(n + '=')); return c ? c.slice(n.length + 1) : null; };
const mkTok = (pre, val, ttl) => { const p = `${val}.${Date.now() + ttl}`; return `${p}.${hmac(pre + p)}`; };
const chkTok = (pre, tok) => {
  if (!tok || !env().SEC) return null;
  const i = tok.lastIndexOf('.'); if (i < 1) return null;
  const p = tok.slice(0, i), sig = tok.slice(i + 1);
  if (!eq(sig, hmac(pre + p))) return null;
  const [val, exp] = p.split('.'); return +exp > Date.now() ? val : null;
};
const setCookie = (res, n, v, secs) => res.setHeader('Set-Cookie', `${n}=${v}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${secs}`);
const isAdmin = req => chkTok('a:', cookie(req, 'sb_admin')) === 'admin';

const scrypt = (pw, salt) => new Promise((ok, no) => crypto.scrypt(pw, salt, 32, (e, k) => e ? no(e) : ok(k.toString('hex'))));
const hashPw = async pw => { const s = crypto.randomBytes(16).toString('hex'); return s + ':' + await scrypt(pw, s); };
const checkPw = async (pw, h) => { const [s, k] = String(h).split(':'); return eq(await scrypt(pw, s), k); };

const hits = {};
const ipOf = req => String(req.headers['x-forwarded-for'] || 'x').split(',')[0].trim();
const limit = (key, max, ms) => { const n = Date.now(), a = (hits[key] || []).filter(t => n - t < ms); if (a.length >= max) fail('Too many attempts. Please try again later.', 429); a.push(n); hits[key] = a; };

module.exports = { sel, ins, upd, del, q, fail, str, modr, cookie, mkTok, chkTok, setCookie, isAdmin, hashPw, checkPw, limit, ipOf, eq, env };
