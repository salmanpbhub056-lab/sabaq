// Vercel serverless function: admin email/password login (no sign-up).
// Set ADMIN_EMAIL, ADMIN_PASSWORD and ADMIN_SECRET (long random string) in Vercel > Settings > Environment Variables.
const crypto = require('crypto');
const eq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const sign = (p, s) => crypto.createHmac('sha256', s).update(p).digest('base64url');
const tries = {};
module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const { ADMIN_EMAIL, ADMIN_PASSWORD, ADMIN_SECRET } = process.env;
  if (!ADMIN_EMAIL || !ADMIN_PASSWORD || !ADMIN_SECRET) return res.status(500).json({ ok: false, error: 'Admin login is not configured.' });
  const ck = (req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith('sb_admin='));
  if (req.method === 'GET') {
    if (ck) { const [p, sig] = ck.slice(9).split('.'); if (p && sig && eq(sig, sign(p, ADMIN_SECRET)) && +p > Date.now()) return res.status(200).json({ ok: true }); }
    return res.status(401).json({ ok: false });
  }
  if (req.method === 'DELETE') {
    res.setHeader('Set-Cookie', 'sb_admin=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0');
    return res.status(200).json({ ok: true });
  }
  if (req.method !== 'POST') return res.status(405).json({ ok: false });
  const ip = String(req.headers['x-forwarded-for'] || 'x').split(',')[0].trim(), t = tries[ip] || { n: 0, u: 0 };
  if (t.u > Date.now()) return res.status(429).json({ ok: false, error: 'Too many attempts. Try again in 15 minutes.' });
  const b = req.body || {};
  const okE = eq(String(b.email || '').trim().toLowerCase(), ADMIN_EMAIL.toLowerCase()), okP = eq(b.password || '', ADMIN_PASSWORD);
  await new Promise(r => setTimeout(r, 400));
  if (okE && okP) {
    delete tries[ip];
    const exp = String(Date.now() + 8 * 3600e3);
    res.setHeader('Set-Cookie', `sb_admin=${exp}.${sign(exp, ADMIN_SECRET)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`);
    return res.status(200).json({ ok: true });
  }
  t.n++; if (t.n >= 5) { t.u = Date.now() + 15 * 60e3; t.n = 0; } tries[ip] = t;
  return res.status(401).json({ ok: false, error: 'Invalid email or password.' });
};
