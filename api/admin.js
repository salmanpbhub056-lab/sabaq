// Admin email/password login (no sign-up). Credentials live in Vercel environment variables.
const { cookie, mkTok, chkTok, setCookie, eq, limit, ipOf } = require('./_lib');
module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const { ADMIN_EMAIL, ADMIN_PASSWORD, ADMIN_SECRET } = process.env;
  if (!ADMIN_EMAIL || !ADMIN_PASSWORD || !ADMIN_SECRET) return res.status(500).json({ ok: false, error: 'Admin login is not configured. Add ADMIN_EMAIL, ADMIN_PASSWORD and ADMIN_SECRET in Vercel, then redeploy.' });
  if (req.method === 'GET') return chkTok('a:', cookie(req, 'sb_admin')) === 'admin' ? res.status(200).json({ ok: true }) : res.status(401).json({ ok: false });
  if (req.method === 'DELETE') { setCookie(res, 'sb_admin', '', 0); return res.status(200).json({ ok: true }); }
  if (req.method !== 'POST') return res.status(405).json({ ok: false });
  try { limit('adm:' + ipOf(req), 8, 15 * 60e3); } catch { return res.status(429).json({ ok: false, error: 'Too many attempts. Try again in 15 minutes.' }); }
  const b = req.body || {};
  const okE = eq(String(b.email || '').trim().toLowerCase(), ADMIN_EMAIL.trim().toLowerCase()), okP = eq(b.password || '', ADMIN_PASSWORD);
  await new Promise(r => setTimeout(r, 400));
  if (okE && okP) { setCookie(res, 'sb_admin', mkTok('a:', 'admin', 8 * 3600e3), 28800); return res.status(200).json({ ok: true }); }
  return res.status(401).json({ ok: false, error: 'Invalid email or password.' });
};
