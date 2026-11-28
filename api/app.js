// Sabaq main API: POST /api/app  { a: "action", ...data }. All rules are enforced here, on the server.
const { sel, ins, upd, del, q, fail, str, modr, cookie, mkTok, chkTok, setCookie, isAdmin, hashPw, checkPw, limit, ipOf, env } = require('./_lib');
const AR = ['DHA', 'Clifton', 'Gulshan-e-Iqbal', 'Gulistan-e-Johar', 'North Nazimabad', 'Nazimabad', 'PECHS', 'Saddar', 'Korangi', 'Malir'];
const LV = ['Matric', 'O Levels', 'A Levels', 'MDCAT', 'ECAT', 'Extras'], MO = ['Home', 'Academy', 'Online'];
const PHV = /^(\+?92|0)3\d{2}[ -]?\d{7}$/, ts = x => new Date(x).getTime(), lim = a => a.length ? a.join(',') : '0';
const getUser = async id => (await sel('users', `id=eq.${q(id)}&select=id,name,email,role,banned`))[0];
const need = async c => { if (!c.uid) fail('Please log in.', 401); const u = await getUser(c.uid); if (!u || u.banned) fail('Please log in.', 401); return u; };
const adminOnly = c => { if (!c.admin) fail('Admin login required.', 401); };
const notify = (uid, text, link) => uid ? ins('notifications', { user_id: uid, text: String(text).slice(0, 300), link: link || '#/me' }) : null;
const audit = t => ins('audit', { text: String(t).slice(0, 300) });
const toL = (r, docs) => ({ id: r.id, uid: r.owner, t: r.type, n: r.name, a: r.area, l: r.levels, s: r.subjects, f: r.fee, m: r.modes, g: r.gender, x: r.exp, r: +r.rating_seed, b: r.bio, h: r.info, ph: r.phone, photo: r.photo || '', st: r.status, note: r.note || '', vs: r.vstatus, feat: r.featured ? 1 : 0, views: r.views, docs: (docs || []).map(d => ({ id: d.id, k: d.kind, name: d.filename, type: d.mime, size: d.size })) });
const toR = r => ({ id: r.id, l: r.listing, uid: r.author, w: r.author_name, s: r.stars, t: r.text, v: 1, d: ts(r.created_at), reply: r.reply || '', ed: r.edited ? 1 : 0 });
const toQ = r => ({ id: r.id, l: r.listing, uid: r.student, n: r.name, p: r.phone, tm: r.time_pref, d: ts(r.created_at), st: r.status });
const H = {};

H.boot = async (b, c) => {
  const me = c.uid ? await getUser(c.uid) : null, u = me && !me.banned ? me : null;
  const rows = await sel('listings', 'select=*&order=id.asc');
  const vis = rows.filter(r => r.status === 'approved' || (u && r.owner === u.id)), mine = vis.filter(r => u && r.owner === u.id).map(r => r.id);
  const docs = mine.length ? await sel('docs', `listing=in.(${lim(mine)})&select=id,listing,kind,filename,mime,size`) : [];
  const ids = new Set(vis.map(r => r.id));
  const rev = (await sel('reviews', 'select=*&order=created_at.desc')).filter(r => ids.has(r.listing)).map(toR);
  let req = [], nt = [];
  if (u) {
    const a = await sel('requests', `student=eq.${q(u.id)}&select=*`), bb = mine.length ? await sel('requests', `listing=in.(${lim(mine)})&select=*`) : [];
    const seen = new Set(); req = [...a, ...bb].filter(r => !seen.has(r.id) && seen.add(r.id)).map(toQ);
    nt = (await sel('notifications', `user_id=eq.${q(u.id)}&select=*&order=created_at.desc&limit=30`)).map(n => ({ id: n.id, uid: n.user_id, t: n.text, link: n.link, d: ts(n.created_at), read: n.read }));
  }
  const groups = await sel('groups', 'select=*&order=id.asc'), gm = await sel('group_members', 'select=*');
  const gr = groups.map(g => ({ id: g.id, n: g.name, ex: g.exam, a: g.area, m: g.base_members + gm.filter(x => x.group_id === g.id).length, j: !!(u && gm.some(x => x.group_id === g.id && x.user_id === u.id)) }));
  const st = await sel('settings', 'key=eq.banner&select=value');
  return { me: u ? { id: u.id, name: u.name, email: u.email, role: u.role } : null, L: vis.map(r => toL(r, docs.filter(d => d.listing === r.id))), rev, req, nt, gr, banner: st[0] ? st[0].value : '' };
};

H.signup = async (b, c) => {
  limit('su:' + ipOf(c.req), 6, 3600e3);
  const name = str(b.n, 50, 2), email = String(b.e || '').trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || email.length > 120) fail('Enter a valid email address.');
  if (!/^(?=.*[A-Za-z])(?=.*\d).{8,100}$/.test(String(b.p || ''))) fail('Password needs 8+ characters with a letter and a number.');
  if (!b.t) fail('Please accept the Terms & rules.');
  if ((await sel('users', `email=eq.${q(email)}&select=id`)).length) fail('An account with this email already exists.');
  const role = b.r === 'provider' ? 'provider' : 'student';
  const [u] = await ins('users', { name, email, pw: await hashPw(b.p), role });
  setCookie(c.res, 'sb_user', mkTok('u:', u.id, 30 * 864e5), 30 * 86400);
  await notify(u.id, 'Welcome to Sabaq! ' + (role === 'provider' ? 'Create your listing to start receiving students.' : 'Search for tutors and request a free demo.'));
  await audit(`New ${role} account: ${email}`); return { ok: true };
};
H.login = async (b, c) => {
  const email = String(b.e || '').trim().toLowerCase();
  limit('li:' + ipOf(c.req) + email, 6, 15 * 60e3);
  const u = (await sel('users', `email=eq.${q(email)}&select=*`))[0];
  if (!u || !(await checkPw(String(b.p || ''), u.pw))) fail('Incorrect email or password.', 401);
  if (u.banned) fail('This account has been suspended. Contact support.', 403);
  setCookie(c.res, 'sb_user', mkTok('u:', u.id, 30 * 864e5), 30 * 86400); return { ok: true };
};
H.logout = async (b, c) => { setCookie(c.res, 'sb_user', '', 0); return { ok: true }; };
H['me.rename'] = async (b, c) => { const u = await need(c); await upd('users', `id=eq.${q(u.id)}`, { name: str(b.n, 50, 2) }); };
H['me.delete'] = async (b, c) => { const u = await need(c); await del('users', `id=eq.${q(u.id)}`); setCookie(c.res, 'sb_user', '', 0); await audit('User deleted own account: ' + u.email); };

const DK = ['degree', 'cnic', 'other'], DT = { 'application/pdf': 1, 'image/jpeg': 1, 'image/png': 1 };
H['listing.save'] = async (b, c) => {
  const u = await need(c); if (u.role !== 'provider') fail('Only tutor or academy accounts can create listings.', 403);
  const id = b.id ? +b.id : 0; let old = null;
  if (id) { old = (await sel('listings', `id=eq.${id}&owner=eq.${q(u.id)}`))[0]; if (!old) fail('Listing not found.', 404); }
  else if ((await sel('listings', `owner=eq.${q(u.id)}&select=id`)).length >= 2) fail('You can have up to 2 listings.');
  const t = b.t === 'a' ? 'a' : 't', name = str(b.n, 60), area = AR.includes(b.a) ? b.a : fail('Choose an area.');
  const levels = [...new Set((Array.isArray(b.l) ? b.l : []).filter(x => LV.includes(x)))]; if (!levels.length) fail('Pick at least one level.');
  const subjects = String(b.s || '').split(',').map(x => x.trim()).filter(Boolean).slice(0, 8).map(x => x.slice(0, 40)); if (!subjects.length) fail('Add at least one subject.');
  const fee = +b.f, exp = +b.x; if (!(fee >= 500 && fee <= 200000)) fail('Fee must be between Rs 500 and Rs 200,000.'); if (!(exp >= 0 && exp <= 60)) fail('Experience must be 0 to 60 years.');
  const modes = [...new Set((Array.isArray(b.m) ? b.m : []).filter(x => MO.includes(x)))]; if (!modes.length) fail('Pick at least one mode.');
  const phone = String(b.ph || ''); if (!/^92\d{10}$/.test(phone)) fail('WhatsApp number must look like 923001234567.');
  const bio = str(b.b, 250, 20), info = str(b.h, 100), mm = modr(bio) || modr(info) || modr(name); if (mm) fail('Name, bio and timings: ' + mm);
  const gender = t === 'a' ? 'B' : (['M', 'F'].includes(b.g) ? b.g : 'M');
  let photo = old ? old.photo : null;
  if (b.photo) { if (typeof b.photo !== 'string' || !b.photo.startsWith('data:image/jpeg;base64,') || b.photo.length > 300000) fail('Photo could not be processed.'); photo = b.photo; }
  const nd = []; for (const d of (Array.isArray(b.docs) ? b.docs : []).slice(0, 3)) {
    if (!DK.includes(d.k) || !DT[d.type] || typeof d.data !== 'string' || !d.data.startsWith(`data:${d.type};base64,`) || d.data.length * .75 > 850000) fail('Each document must be a PDF, JPG or PNG under 800 KB.');
    nd.push({ kind: d.k, filename: String(d.name || 'file').slice(0, 60), mime: d.type, size: Math.min(+d.size || 0, 850000), data: d.data });
  }
  const row = { type: t, name, area, levels, subjects, fee, modes, gender, exp, bio, info, phone, photo, status: 'pending', note: '' };
  let L; if (old) { [L] = await upd('listings', `id=eq.${old.id}`, row); } else { [L] = await ins('listings', { owner: u.id, ...row }); }
  for (const d of nd) { await del('docs', `listing=eq.${L.id}&kind=eq.${d.kind}`); await ins('docs', { listing: L.id, ...d }); }
  const kinds = (await sel('docs', `listing=eq.${L.id}&select=kind`)).map(x => x.kind), full = kinds.includes('degree') && kinds.includes('cnic');
  await upd('listings', `id=eq.${L.id}`, { vstatus: full ? (old && old.vstatus === 'verified' && !nd.length ? 'verified' : 'pending') : 'none' });
  await audit((old ? 'Listing updated: ' : 'New listing: ') + name); return { ok: true, id: L.id };
};
H['listing.delete'] = async (b, c) => { const u = await need(c); const x = (await sel('listings', `id=eq.${+b.id}&owner=eq.${q(u.id)}&select=id`))[0]; if (!x) fail('Listing not found.', 404); await del('listings', `id=eq.${x.id}`); };
H.view = async (b, c) => { const id = +b.id, x = (await sel('listings', `id=eq.${id}&select=id,owner,status,views`))[0]; if (x && x.status === 'approved' && x.owner !== c.uid) await upd('listings', `id=eq.${id}`, { views: x.views + 1 }); return { ok: true }; };

H['request.create'] = async (b, c) => {
  const u = await need(c), l = +b.l, x = (await sel('listings', `id=eq.${l}`))[0];
  if (!x || x.status !== 'approved') fail('This listing is not available.', 404); if (x.owner === u.id) fail('You cannot request your own listing.');
  const phone = String(b.p || '').trim(); if (!PHV.test(phone)) fail('Enter a valid Pakistani mobile number.');
  const name = str(b.n, 40), mine = await sel('requests', `student=eq.${q(u.id)}&select=listing,status,created_at`);
  if (mine.some(r => r.listing === l && ['new', 'accepted'].includes(r.status))) fail('You already have an active request for this listing.');
  if (mine.filter(r => Date.now() - ts(r.created_at) < 864e5).length >= 5) fail('Daily limit reached (5 requests). Try again tomorrow.');
  await ins('requests', { listing: l, student: u.id, name, phone, time_pref: String(b.tm || '').slice(0, 60) });
  await notify(x.owner, `${name} requested a demo class.`);
};
H['request.cancel'] = async (b, c) => { const u = await need(c); await upd('requests', `id=eq.${q(b.id)}&student=eq.${q(u.id)}&status=eq.new`, { status: 'cancelled' }); };
H['request.set'] = async (b, c) => {
  const u = await need(c); if (!['accepted', 'declined'].includes(b.st)) fail('Invalid status.');
  const r = (await sel('requests', `id=eq.${q(b.id)}`))[0]; if (!r) fail('Not found.', 404);
  const x = (await sel('listings', `id=eq.${r.listing}&select=name,owner`))[0]; if (!x || x.owner !== u.id) fail('Not allowed.', 403);
  await upd('requests', `id=eq.${q(r.id)}`, { status: b.st }); await notify(r.student, `Your demo request to ${x.name} was ${b.st}.`);
};
H['review.create'] = async (b, c) => {
  const u = await need(c), l = +b.l, x = (await sel('listings', `id=eq.${l}`))[0]; if (!x || x.status !== 'approved') fail('This listing is not available.', 404); if (x.owner === u.id) fail('You cannot review your own listing.');
  if (!(await sel('requests', `listing=eq.${l}&student=eq.${q(u.id)}&select=status`)).some(r => ['new', 'accepted'].includes(r.status))) fail('Request a demo first. Only students with a demo request can review.');
  if ((await sel('reviews', `listing=eq.${l}&author=eq.${q(u.id)}&select=id`)).length) fail('You already reviewed this listing.');
  const text = str(b.t, 300, 10), m = modr(text); if (m) fail(m); const stars = Math.min(5, Math.max(1, Math.round(+b.s || 5)));
  await ins('reviews', { listing: l, author: u.id, author_name: u.name.split(' ')[0] + ' (student)', stars, text }); await notify(x.owner, 'You received a new review.');
};
H['review.edit'] = async (b, c) => { const u = await need(c), text = str(b.t, 300, 10), m = modr(text); if (m) fail(m); await upd('reviews', `id=eq.${q(b.id)}&author=eq.${q(u.id)}`, { text, edited: true }); };
H['review.delete'] = async (b, c) => { const u = await need(c); await del('reviews', `id=eq.${q(b.id)}&author=eq.${q(u.id)}`); };
H['review.reply'] = async (b, c) => {
  const u = await need(c), r = (await sel('reviews', `id=eq.${q(b.id)}`))[0]; if (!r) fail('Not found.', 404);
  const x = (await sel('listings', `id=eq.${r.listing}&select=owner`))[0]; if (!x || x.owner !== u.id) fail('Not allowed.', 403);
  const text = str(b.t, 300), m = modr(text); if (m) fail(m); await upd('reviews', `id=eq.${q(r.id)}`, { reply: text }); await notify(r.author, 'A tutor replied to your review.', '#/p/' + r.listing);
};
H['report.create'] = async (b, c) => {
  const u = await need(c), l = +b.l; if (!(await sel('listings', `id=eq.${l}&select=id`)).length) fail('Not found.', 404);
  if ((await sel('reports', `listing=eq.${l}&reporter=eq.${q(u.id)}&status=eq.open&select=id`)).length) fail('You already reported this listing.');
  await ins('reports', { listing: l, reporter: u.id, reason: str(b.r, 60), details: str(b.t, 300, 10) }); await audit('New report on listing #' + l);
};
H['notif.read'] = async (b, c) => { const u = await need(c); await upd('notifications', `user_id=eq.${q(u.id)}${b.all ? '' : '&id=eq.' + q(b.id)}`, { read: true }); };
H['group.join'] = async (b, c) => {
  const u = await need(c), g = +b.id, k = `group_id=eq.${g}&user_id=eq.${q(u.id)}`;
  if ((await sel('group_members', k)).length) await del('group_members', k); else await ins('group_members', { group_id: g, user_id: u.id });
};
H['group.create'] = async (b, c) => {
  const u = await need(c), exam = LV.includes(b.ex) ? b.ex : fail('Choose an exam.'), area = AR.includes(b.a) ? b.a : fail('Choose an area.');
  const [g] = await ins('groups', { name: str(b.n, 60, 3), exam, area }); await ins('group_members', { group_id: g.id, user_id: u.id });
};

// ---------- admin ----------
H['admin.data'] = async (b, c) => {
  adminOnly(c);
  const us = await sel('users', 'select=id,name,email,role,banned,created_at&order=created_at.desc'), rows = await sel('listings', 'select=*&order=id.asc'), docs = await sel('docs', 'select=id,listing,kind,filename,mime,size');
  const rep = await sel('reports', 'select=*&order=created_at.desc'), rev = await sel('reviews', 'select=*&order=created_at.desc'), au = await sel('audit', 'select=*&order=created_at.desc&limit=200'), rq = await sel('requests', 'select=id');
  return { us: us.map(u => ({ id: u.id, name: u.name, email: u.email, role: u.role, ban: u.banned ? 1 : 0, created: ts(u.created_at) })), L: rows.map(r => toL(r, docs.filter(d => d.listing === r.id))), rep: rep.map(r => ({ id: r.id, l: r.listing, uid: r.reporter, r: r.reason, d: r.details, t: ts(r.created_at), st: r.status })), rev: rev.map(toR), au: au.map(a => ({ d: ts(a.created_at), a: a.text })), rc: rq.length };
};
H['admin.doc'] = async (b, c) => { adminOnly(c); const d = (await sel('docs', `id=eq.${q(b.id)}`))[0]; if (!d) fail('Document not found.', 404); return { data: d.data, type: d.mime, name: d.filename }; };
H['admin.listing'] = async (b, c) => {
  adminOnly(c); const id = +b.id, x = (await sel('listings', `id=eq.${id}`))[0]; if (!x) fail('Not found.', 404);
  const note = String(b.note || '').trim().slice(0, 300), op = b.op, kinds = (await sel('docs', `listing=eq.${id}&select=kind`)).map(d => d.kind);
  if (op === 'ver' && x.owner && !(kinds.includes('degree') && kinds.includes('cnic'))) fail('Degree and ID documents are required to verify.');
  if ((op === 'no' || op === 'sus') && note.length < 5) fail('Add a reason (min 5 characters).');
  const P = { ok: [{ status: 'approved', note: '' }, 'Your listing was approved and is now live.'], ver: [{ status: 'approved', vstatus: 'verified', note: '' }, 'Your listing was approved and verified.'], no: [{ status: 'rejected', note, vstatus: x.vstatus === 'pending' ? 'none' : x.vstatus }, 'Your listing was rejected: ' + note], sus: [{ status: 'suspended', note }, 'Your listing was suspended: ' + note], unv: [{ vstatus: 'none' }, 'Your verification badge was removed.'], feat: [{ featured: !x.featured }] }[op];
  if (op === 'del') { if (!x.owner) fail('Sample listings cannot be deleted. Suspend instead.'); await del('listings', `id=eq.${id}`); }
  else { if (!P) fail('Unknown action.'); await upd('listings', `id=eq.${id}`, P[0]); if (P[1] && x.owner) await notify(x.owner, P[1]); }
  await audit(`${String(op).toUpperCase()}: ${x.name}${note ? ' (' + note + ')' : ''}`);
};
H['admin.user'] = async (b, c) => {
  adminOnly(c); const u = (await sel('users', `id=eq.${q(b.id)}&select=id,email,banned`))[0]; if (!u) fail('Not found.', 404);
  if (b.op === 'del') { await del('users', `id=eq.${q(u.id)}`); await audit('Deleted user ' + u.email); }
  else { await upd('users', `id=eq.${q(u.id)}`, { banned: !u.banned }); await audit((u.banned ? 'Reinstated user ' : 'Suspended user ') + u.email); }
};
H['admin.review.del'] = async (b, c) => { adminOnly(c); await del('reviews', `id=eq.${q(b.id)}`); await audit('Removed a review'); };
H['admin.report'] = async (b, c) => {
  adminOnly(c); const r = (await sel('reports', `id=eq.${q(b.id)}`))[0]; if (!r) fail('Not found.', 404); const st = b.op === 'suspended' ? 'suspended' : 'dismissed';
  if (st === 'suspended') { const x = (await sel('listings', `id=eq.${r.listing}&select=id,owner`))[0]; if (x) { await upd('listings', `id=eq.${x.id}`, { status: 'suspended', note: 'Suspended after a report: ' + r.reason }); await notify(x.owner, 'Your listing was suspended after a report. Contact support.'); } }
  await upd('reports', `id=eq.${q(r.id)}`, { status: st }); await audit('Report ' + st);
};
H['admin.banner'] = async (b, c) => { adminOnly(c); const v = String(b.text || '').trim().slice(0, 140); await del('settings', 'key=eq.banner'); await ins('settings', { key: 'banner', value: v }); await audit('Announcement updated'); };

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const E = env(); if (!E.SB || !E.KEY || !E.SEC) return res.status(500).json({ error: 'Server is not set up yet. Add the environment variables in Vercel and redeploy.' });
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });
  const b = req.body && typeof req.body === 'object' ? req.body : {}, h = H[String(b._a || '')]; if (!h) return res.status(400).json({ error: 'Unknown action' });
  try { const out = await h(b, { req, res, uid: chkTok('u:', cookie(req, 'sb_user')), admin: isAdmin(req) }); return res.status(200).json(out || { ok: true }); }
  catch (e) { if (e.user) return res.status(e.code || 400).json({ error: e.message }); console.error(e); return res.status(500).json({ error: 'Something went wrong. Please try again.' }); }
};
