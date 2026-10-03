'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { config } = require('./config');
const { db, tx, bumpContentVersion, contentVersion, recomputeFreeFlags } = require('./db');
const { hashPassword, verifyPassword, DUMMY_HASH, signToken, verifyToken, rateLimit, normalizePhone, clean } = require('./security');
const { HttpError, Router } = require('./http');

const GRADES = ['6', '8'];
const nowIso = () => new Date().toISOString();
const addDays = (iso, days) => new Date(new Date(iso).getTime() + days * 86400000).toISOString();

/* ---------- helpers ---------- */
function audit(userId, action, detail, ip) {
  try { db.prepare('INSERT INTO audit_log(user_id,action,detail,ip,created_at) VALUES(?,?,?,?,?)').run(userId || null, action, detail ? String(detail).slice(0, 500) : null, ip || null, nowIso()); } catch (_) {}
}
function limit(key, max, windowMs, message) {
  const r = rateLimit(key, max, windowMs);
  if (!r.allowed) throw new HttpError(429, message || 'Too many requests. Please try again later.', { retryAfter: r.retryAfter });
}
function authenticate(ctx, required = true) {
  const header = String(ctx.req.headers.authorization || '');
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  const payload = token ? verifyToken(token) : null;
  let user = null;
  if (payload) {
    user = db.prepare('SELECT * FROM users WHERE id = ?').get(payload.sub);
    if (user && user.token_version !== payload.tv) user = null;
  }
  if (!user && required) throw new HttpError(401, 'Please log in again.');
  ctx.user = user;
  return user;
}
function requireAdmin(ctx) {
  const user = authenticate(ctx);
  if (user.role !== 'admin') throw new HttpError(403, 'Admins only.');
  return user;
}
function premiumMap(user) {
  const out = { 6: { active: false, expiry: null }, 8: { active: false, expiry: null } };
  if (user.role === 'admin') return { 6: { active: true, expiry: null }, 8: { active: true, expiry: null } };
  const now = nowIso();
  for (const row of db.prepare('SELECT grade, expires_at FROM premium WHERE user_id = ?').all(user.id)) {
    out[row.grade] = { active: row.expires_at > now, expiry: row.expires_at };
  }
  return out;
}
function userView(user) {
  return { id: user.id, phone: user.phone, firstName: user.first_name, lastName: user.last_name, role: user.role, grade: user.grade, region: user.region, premium: premiumMap(user) };
}
function tokenFor(user) { return signToken({ sub: user.id, tv: user.token_version }); }
function parseQuestion(r) {
  return { id: r.id, subject: r.subject, grade: r.grade, year: r.year, region: r.region, chapter: r.chapter, q: r.q, options: JSON.parse(r.options), answer: r.answer, explanation: r.explanation, difficulty: r.difficulty, passage: r.passage, image: r.image };
}
function questionHash(q) {
  return crypto.createHash('sha1').update([q.subject, q.grade, q.year, q.region, q.q, q.options.join('\u241f')].join('\u241e')).digest('hex');
}
function str(v, field, max, { required = true } = {}) {
  const s = clean(v, max);
  if (required && !s) throw new HttpError(400, `${field} is required.`);
  return s;
}
function intIn(v, min, max, field) {
  const n = Number(v);
  if (!Number.isInteger(n) || n < min || n > max) throw new HttpError(400, `${field} is invalid.`);
  return n;
}
function grantPremium(userId, grades, days) {
  const now = nowIso();
  for (const g of grades) {
    const cur = db.prepare('SELECT expires_at FROM premium WHERE user_id = ? AND grade = ?').get(userId, g);
    const base = cur && cur.expires_at > now ? cur.expires_at : now;
    db.prepare('INSERT INTO premium(user_id,grade,expires_at) VALUES(?,?,?) ON CONFLICT(user_id,grade) DO UPDATE SET expires_at=excluded.expires_at').run(userId, g, addDays(base, days));
  }
}
const IMAGE_SIGNATURES = [
  { ext: 'png', mime: 'image/png', test: b => b.length > 8 && b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47 },
  { ext: 'jpg', mime: 'image/jpeg', test: b => b.length > 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff },
  { ext: 'webp', mime: 'image/webp', test: b => b.length > 12 && b.slice(0, 4).toString() === 'RIFF' && b.slice(8, 12).toString() === 'WEBP' },
];
function decodeImage(dataUrl) {
  const m = /^data:image\/(png|jpeg|jpg|webp);base64,([A-Za-z0-9+/=\s]+)$/.exec(String(dataUrl || ''));
  if (!m) throw new HttpError(400, 'Upload a PNG, JPG or WEBP screenshot.');
  const buf = Buffer.from(m[2], 'base64');
  if (buf.length === 0 || buf.length > config.maxScreenshotBytes) throw new HttpError(413, 'Screenshot is too large (max 3 MB).');
  const sig = IMAGE_SIGNATURES.find(s => s.test(buf));
  if (!sig) throw new HttpError(400, 'That file is not a valid image.');
  return { buf, ...sig };
}

/* ---------- routes ---------- */
function buildRouter() {
  const r = new Router();

  r.add('GET', '/health', async () => ({ ok: true, time: nowIso(), contentVersion: contentVersion() }));

  r.add('GET', '/api/config', async () => ({
    plans: config.plans.map(p => ({ id: p.id, label: p.label, price: p.price, currency: 'ETB' })),
    paymentMethods: config.paymentMethods.filter(m => m.account),
    subscriptionDays: config.subscriptionDays,
    freeQuestionsPerExam: config.freeQuestions,
    support: config.support,
    contentVersion: contentVersion(),
  }));

  /* ----- auth ----- */
  r.add('POST', '/api/auth/register', async ctx => {
    limit('reg:' + ctx.ip, 10, 3600_000, 'Too many sign-ups from this network. Try again later.');
    const b = ctx.body;
    const phone = normalizePhone(b.phone);
    if (!phone) throw new HttpError(400, 'Enter a valid Ethiopian phone number (e.g. 09XXXXXXXX).');
    const password = String(b.password || '');
    if (password.length < 6 || password.length > 100) throw new HttpError(400, 'Password must be 6–100 characters.');
    const grade = ['6', '8', 'both'].includes(String(b.grade)) ? String(b.grade) : '8';
    const first = clean(b.firstName, 40) || 'Student';
    const last = clean(b.lastName, 40);
    if (db.prepare('SELECT 1 FROM users WHERE phone = ?').get(phone)) throw new HttpError(409, 'An account with this phone already exists. Please log in.');
    const info = db.prepare('INSERT INTO users(phone,first_name,last_name,pass_hash,role,grade,created_at,last_login_at) VALUES(?,?,?,?,?,?,?,?)')
      .run(phone, first, last, hashPassword(password), 'student', grade, nowIso(), nowIso());
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
    audit(user.id, 'register', phone, ctx.ip);
    return { status: 201, body: { token: tokenFor(user), user: userView(user) } };
  });

  r.add('POST', '/api/auth/login', async ctx => {
    limit('login-ip:' + ctx.ip, 30, 600_000, 'Too many login attempts. Wait a few minutes.');
    const phone = normalizePhone(ctx.body.phone);
    const password = String(ctx.body.password || '');
    if (!phone || !password) throw new HttpError(400, 'Enter your phone number and password.');
    limit('login-phone:' + phone, 8, 900_000, 'Too many attempts for this account. Wait 15 minutes.');
    const user = db.prepare('SELECT * FROM users WHERE phone = ?').get(phone);
    const ok = verifyPassword(password, user ? user.pass_hash : DUMMY_HASH) && !!user;
    if (!ok) { audit(user && user.id, 'login_failed', phone, ctx.ip); throw new HttpError(401, 'Invalid phone number or password.'); }
    db.prepare('UPDATE users SET last_login_at = ? WHERE id = ?').run(nowIso(), user.id);
    return { token: tokenFor(user), user: userView(user) };
  });

  r.add('POST', '/api/auth/logout-all', async ctx => {
    const user = authenticate(ctx);
    db.prepare('UPDATE users SET token_version = token_version + 1 WHERE id = ?').run(user.id);
    audit(user.id, 'logout_all', null, ctx.ip);
    return { ok: true };
  });

  r.add('GET', '/api/me', async ctx => ({ user: userView(authenticate(ctx)) }));

  r.add('PATCH', '/api/me', async ctx => {
    const user = authenticate(ctx);
    const b = ctx.body;
    const sets = []; const vals = [];
    if (b.region !== undefined) { const reg = String(b.region); if (!/^[a-z][a-z-]{1,30}$/.test(reg)) throw new HttpError(400, 'Invalid region.'); sets.push('region = ?'); vals.push(reg); }
    if (b.firstName !== undefined) { sets.push('first_name = ?'); vals.push(str(b.firstName, 'First name', 40)); }
    if (b.lastName !== undefined) { sets.push('last_name = ?'); vals.push(clean(b.lastName, 40)); }
    if (b.grade !== undefined) { if (!['6', '8', 'both'].includes(String(b.grade))) throw new HttpError(400, 'Invalid grade.'); sets.push('grade = ?'); vals.push(String(b.grade)); }
    if (sets.length) db.prepare(`UPDATE users SET ${sets.join(', ')} WHERE id = ?`).run(...vals, user.id);
    return { user: userView(db.prepare('SELECT * FROM users WHERE id = ?').get(user.id)) };
  });

  r.add('DELETE', '/api/me', async ctx => {
    // DELETE requests carry no body in readJson(), so the password is sent in a header.
    const user = authenticate(ctx);
    limit('del:' + user.id, 5, 900_000);
    if (user.role === 'admin') throw new HttpError(403, 'Admin accounts cannot be deleted here.');
    const password = String(ctx.req.headers['x-confirm-password'] || '');
    if (!verifyPassword(password, user.pass_hash)) throw new HttpError(401, 'Password is wrong.');
    const files = db.prepare('SELECT screenshot_file FROM payments WHERE user_id = ?').all(user.id);
    tx(() => { db.prepare('DELETE FROM users WHERE id = ?').run(user.id); });
    for (const f of files) { try { fs.unlinkSync(path.join(config.uploadDir, 'payments', path.basename(f.screenshot_file))); } catch (_) {} }
    audit(null, 'account_deleted', 'user ' + user.id, ctx.ip);
    return { ok: true };
  });

  r.add('POST', '/api/me/password', async ctx => {
    const user = authenticate(ctx);
    limit('pw:' + user.id, 5, 900_000);
    if (!verifyPassword(String(ctx.body.oldPassword || ''), user.pass_hash)) throw new HttpError(401, 'Current password is wrong.');
    const np = String(ctx.body.newPassword || '');
    if (np.length < 6 || np.length > 100) throw new HttpError(400, 'New password must be 6–100 characters.');
    db.prepare('UPDATE users SET pass_hash = ?, token_version = token_version + 1 WHERE id = ?').run(hashPassword(np), user.id);
    const fresh = db.prepare('SELECT * FROM users WHERE id = ?').get(user.id);
    audit(user.id, 'password_changed', null, ctx.ip);
    return { token: tokenFor(fresh), user: userView(fresh) };
  });

  /* ----- content ----- */
  r.add('GET', '/api/content/manifest', async ctx => {
    authenticate(ctx);
    const region = clean(ctx.query.region || 'sidama', 30);
    const subjects = db.prepare('SELECT * FROM subjects').all().map(s => ({ id: s.id, name: s.name, icon: s.icon, icon2: s.icon2, gradient: s.gradient, grades: s.grades ? JSON.parse(s.grades) : null }));
    const exams = db.prepare('SELECT subject, grade, year, COUNT(*) AS count, SUM(is_free) AS freeCount FROM questions WHERE region = ? GROUP BY subject, grade, year ORDER BY year DESC').all(region);
    const chapters = db.prepare('SELECT subject, grade, year, chapter AS name, COUNT(*) AS count FROM questions WHERE region = ? GROUP BY subject, grade, year, chapter ORDER BY subject, grade, year, MIN(id)').all(region);
    return { contentVersion: contentVersion(), region, subjects, exams, chapters };
  });

  r.add('GET', '/api/questions', async ctx => {
    const user = authenticate(ctx);
    const q = ctx.query;
    const grade = String(q.grade || '');
    if (!GRADES.includes(grade)) throw new HttpError(400, 'grade must be 6 or 8.');
    const subject = str(q.subject, 'subject', 40);
    limit('qs:' + user.id, 240, 600_000, 'Slow down a little.');
    const where = ['subject = ?', 'grade = ?', 'region = ?']; const args = [subject, grade, clean(q.region || 'sidama', 30)];
    if (q.year) { where.push('year = ?'); args.push(clean(q.year, 20)); }
    if (q.chapter) { where.push('chapter = ?'); args.push(clean(q.chapter, 200)); }
    if (q.difficulty) { where.push('difficulty = ?'); args.push(clean(q.difficulty, 10)); }
    const premium = premiumMap(user)[grade].active;
    const all = db.prepare(`SELECT COUNT(*) AS n FROM questions WHERE ${where.join(' AND ')}`).get(...args).n;
    if (!premium) where.push('is_free = 1');
    const random = q.random === '1';
    const count = Math.min(Math.max(parseInt(q.count, 10) || 0, 0), 200);
    const sql = `SELECT * FROM questions WHERE ${where.join(' AND ')} ORDER BY ${random ? 'RANDOM()' : 'id'}${count ? ' LIMIT ' + count : ''}`;
    const rows = db.prepare(sql).all(...args).map(parseQuestion);
    return { questions: rows, total: all, premium, locked: !premium && all > rows.length, lockedCount: premium ? 0 : Math.max(all - rows.length, 0) };
  });

  r.add('GET', '/api/books', async ctx => { authenticate(ctx); const g = ctx.query.grade; return { books: g ? db.prepare('SELECT subject,grade,title,file FROM books WHERE grade = ?').all(String(g)) : db.prepare('SELECT subject,grade,title,file FROM books').all() }; });
  r.add('GET', '/api/videos', async ctx => { authenticate(ctx); const g = ctx.query.grade; return { videos: g ? db.prepare('SELECT subject,grade,title,url FROM videos WHERE grade = ?').all(String(g)) : db.prepare('SELECT subject,grade,title,url FROM videos').all() }; });

  /* ----- payments (manual CBE / Telebirr screenshot review) ----- */
  r.add('POST', '/api/payments', async ctx => {
    const user = authenticate(ctx);
    limit('pay:' + user.id, 10, 3600_000, 'Too many payment submissions. Try again later.');
    const plan = config.plans.find(p => p.id === String(ctx.body.plan));
    if (!plan) throw new HttpError(400, 'Choose a valid plan.');
    const method = config.paymentMethods.find(m => m.id === String(ctx.body.method));
    if (!method) throw new HttpError(400, 'Choose a valid payment method.');
    const pending = db.prepare("SELECT COUNT(*) AS n FROM payments WHERE user_id = ? AND status = 'pending'").get(user.id).n;
    if (pending >= 3) throw new HttpError(429, 'You already have pending payments waiting for review.');
    const img = decodeImage(ctx.body.screenshot);
    const hash = crypto.createHash('sha256').update(img.buf).digest('hex');
    const reference = clean(ctx.body.reference, 40);
    const flags = [];
    if (db.prepare("SELECT 1 FROM payments WHERE screenshot_hash = ? AND status != 'rejected'").get(hash)) flags.push('duplicate_screenshot');
    if (reference && db.prepare("SELECT 1 FROM payments WHERE reference = ? AND status = 'approved'").get(reference)) flags.push('duplicate_reference');
    const file = crypto.randomBytes(16).toString('hex') + '.' + img.ext;
    fs.writeFileSync(path.join(config.uploadDir, 'payments', file), img.buf, { mode: 0o600 });
    const info = db.prepare('INSERT INTO payments(user_id,plan,amount,method,reference,screenshot_file,screenshot_hash,flag,created_at) VALUES(?,?,?,?,?,?,?,?,?)')
      .run(user.id, plan.id, plan.price, method.id, reference || null, file, hash, flags.join(',') || null, nowIso());
    audit(user.id, 'payment_submitted', `#${info.lastInsertRowid} ${plan.id} ${plan.price}`, ctx.ip);
    return { status: 201, body: { id: Number(info.lastInsertRowid), status: 'pending', amount: plan.price } };
  });

  r.add('GET', '/api/payments/mine', async ctx => {
    const user = authenticate(ctx);
    return { payments: db.prepare('SELECT id, plan, amount, method, status, note, created_at, reviewed_at FROM payments WHERE user_id = ? ORDER BY id DESC LIMIT 50').all(user.id) };
  });

  /* ----- exercise history ----- */
  r.add('POST', '/api/history', async ctx => {
    const user = authenticate(ctx);
    limit('hist:' + user.id, 120, 3600_000);
    const b = ctx.body;
    const grade = String(b.grade);
    if (!GRADES.includes(grade)) throw new HttpError(400, 'Invalid grade.');
    const total = intIn(b.total, 0, 500, 'total');
    const answered = intIn(b.answered, 0, total, 'answered');
    const correct = intIn(b.correct, 0, answered, 'correct');
    const wrong = intIn(b.wrong, 0, answered, 'wrong');
    const percentage = total ? Math.round((correct / total) * 100) : 0;
    let detail = null;
    if (b.detail !== undefined) { detail = JSON.stringify(b.detail); if (detail.length > 200_000) throw new HttpError(413, 'History detail too large.'); }
    const info = db.prepare('INSERT INTO history(user_id,grade,subject,year,mode,total,answered,correct,wrong,percentage,time_taken_sec,detail,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)')
      .run(user.id, grade, str(b.subject, 'subject', 40), str(b.year, 'year', 200), str(b.mode, 'mode', 20), total, answered, correct, wrong, percentage, intIn(b.timeTakenSec || 0, 0, 86400, 'timeTakenSec'), detail, nowIso());
    return { status: 201, body: { id: Number(info.lastInsertRowid), percentage } };
  });

  r.add('GET', '/api/history', async ctx => {
    const user = authenticate(ctx);
    const rows = ctx.query.grade
      ? db.prepare('SELECT id,grade,subject,year,mode,total,answered,correct,wrong,percentage,time_taken_sec,created_at FROM history WHERE user_id = ? AND grade = ? ORDER BY id DESC LIMIT 100').all(user.id, String(ctx.query.grade))
      : db.prepare('SELECT id,grade,subject,year,mode,total,answered,correct,wrong,percentage,time_taken_sec,created_at FROM history WHERE user_id = ? ORDER BY id DESC LIMIT 100').all(user.id);
    return { history: rows };
  });

  /* ================= ADMIN ================= */
  r.add('GET', '/api/admin/stats', async ctx => {
    requireAdmin(ctx);
    const n = sql => db.prepare(sql).get().n;
    return {
      users: n("SELECT COUNT(*) AS n FROM users WHERE role = 'student'"),
      premiumUsers: n("SELECT COUNT(DISTINCT user_id) AS n FROM premium WHERE expires_at > '" + nowIso() + "'"),
      pendingPayments: n("SELECT COUNT(*) AS n FROM payments WHERE status = 'pending'"),
      approvedRevenueETB: n("SELECT COALESCE(SUM(amount),0) AS n FROM payments WHERE status = 'approved'"),
      questions: n('SELECT COUNT(*) AS n FROM questions'),
      unverifiedAnswers: n('SELECT COUNT(*) AS n FROM questions WHERE answer < 0'),
    };
  });

  r.add('GET', '/api/admin/users', async ctx => {
    requireAdmin(ctx);
    const page = Math.max(parseInt(ctx.query.page, 10) || 1, 1); const size = Math.min(Math.max(parseInt(ctx.query.pageSize, 10) || 25, 1), 100);
    const term = '%' + clean(ctx.query.q, 40).replace(/[%_]/g, '') + '%';
    const rows = db.prepare('SELECT id,phone,first_name,last_name,role,grade,region,created_at,last_login_at FROM users WHERE phone LIKE ? OR first_name LIKE ? OR last_name LIKE ? ORDER BY id DESC LIMIT ? OFFSET ?').all(term, term, term, size, (page - 1) * size);
    return { users: rows.map(u => ({ ...u, premium: premiumMap(db.prepare('SELECT * FROM users WHERE id = ?').get(u.id)) })), page };
  });

  r.add('POST', '/api/admin/users/:id/premium', async ctx => {
    const admin = requireAdmin(ctx);
    const target = db.prepare('SELECT * FROM users WHERE id = ?').get(ctx.params.id);
    if (!target) throw new HttpError(404, 'User not found.');
    const grades = ctx.body.grade === 'both' ? GRADES : [String(ctx.body.grade)];
    if (!grades.every(g => GRADES.includes(g))) throw new HttpError(400, 'Invalid grade.');
    if (ctx.body.revoke) { for (const g of grades) db.prepare('DELETE FROM premium WHERE user_id = ? AND grade = ?').run(target.id, g); }
    else grantPremium(target.id, grades, intIn(ctx.body.days || config.subscriptionDays, 1, 3650, 'days'));
    audit(admin.id, ctx.body.revoke ? 'premium_revoked' : 'premium_granted', `user ${target.id} grades ${grades.join('+')}`, ctx.ip);
    return { user: userView(target) };
  });

  r.add('GET', '/api/admin/payments', async ctx => {
    requireAdmin(ctx);
    const status = ['pending', 'approved', 'rejected'].includes(ctx.query.status) ? ctx.query.status : null;
    const rows = db.prepare(`SELECT p.id,p.plan,p.amount,p.method,p.reference,p.status,p.flag,p.note,p.created_at,p.reviewed_at,u.id AS user_id,u.phone,u.first_name,u.last_name FROM payments p JOIN users u ON u.id = p.user_id ${status ? 'WHERE p.status = ?' : ''} ORDER BY p.id DESC LIMIT 200`).all(...(status ? [status] : []));
    return { payments: rows };
  });

  r.add('GET', '/api/admin/payments/:id/screenshot', async ctx => {
    requireAdmin(ctx);
    const p = db.prepare('SELECT screenshot_file FROM payments WHERE id = ?').get(ctx.params.id);
    if (!p) throw new HttpError(404, 'Not found.');
    const file = path.join(config.uploadDir, 'payments', path.basename(p.screenshot_file));
    if (!fs.existsSync(file)) throw new HttpError(404, 'Screenshot file is missing.');
    const ext = path.extname(file).slice(1);
    return { raw: fs.readFileSync(file), headers: { 'Content-Type': ext === 'png' ? 'image/png' : ext === 'webp' ? 'image/webp' : 'image/jpeg' } };
  });

  r.add('POST', '/api/admin/payments/:id/approve', async ctx => {
    const admin = requireAdmin(ctx);
    return tx(() => {
      const p = db.prepare('SELECT * FROM payments WHERE id = ?').get(ctx.params.id);
      if (!p) throw new HttpError(404, 'Payment not found.');
      if (p.status !== 'pending') throw new HttpError(409, `This payment is already ${p.status}.`);
      const plan = config.plans.find(x => x.id === p.plan);
      if (!plan) throw new HttpError(500, 'Plan no longer exists.');
      db.prepare("UPDATE payments SET status = 'approved', reviewed_at = ?, reviewed_by = ?, note = ? WHERE id = ?").run(nowIso(), admin.id, clean(ctx.body.note, 200) || null, p.id);
      grantPremium(p.user_id, plan.grades, config.subscriptionDays);
      audit(admin.id, 'payment_approved', `#${p.id}`, ctx.ip);
      return { ok: true, user: userView(db.prepare('SELECT * FROM users WHERE id = ?').get(p.user_id)) };
    });
  });

  r.add('POST', '/api/admin/payments/:id/reject', async ctx => {
    const admin = requireAdmin(ctx);
    const p = db.prepare('SELECT * FROM payments WHERE id = ?').get(ctx.params.id);
    if (!p) throw new HttpError(404, 'Payment not found.');
    if (p.status !== 'pending') throw new HttpError(409, `This payment is already ${p.status}.`);
    db.prepare("UPDATE payments SET status = 'rejected', reviewed_at = ?, reviewed_by = ?, note = ? WHERE id = ?").run(nowIso(), admin.id, clean(ctx.body.note, 200) || 'Rejected', p.id);
    audit(admin.id, 'payment_rejected', `#${p.id}`, ctx.ip);
    return { ok: true };
  });

  /* ----- admin: questions ----- */
  function readQuestionBody(b, existing) {
    const subject = str(b.subject ?? existing?.subject, 'subject', 40);
    if (!db.prepare('SELECT 1 FROM subjects WHERE id = ?').get(subject)) throw new HttpError(400, 'Unknown subject.');
    const grade = String(b.grade ?? existing?.grade);
    if (!GRADES.includes(grade)) throw new HttpError(400, 'grade must be 6 or 8.');
    const options = (b.options ?? (existing && JSON.parse(existing.options)));
    if (!Array.isArray(options) || options.length < 2 || options.length > 6 || options.some(o => typeof o !== 'string' || !o.trim())) throw new HttpError(400, 'Provide 2–6 non-empty options.');
    const opts = options.map(o => o.trim().slice(0, 600));
    if (new Set(opts).size !== opts.length) throw new HttpError(400, 'Options must all be different.');
    const answer = intIn(b.answer ?? existing?.answer ?? -1, -1, opts.length - 1, 'answer');
    return {
      subject, grade, year: str(b.year ?? existing?.year, 'year', 20), region: str(b.region ?? existing?.region ?? 'sidama', 'region', 30),
      chapter: str(b.chapter ?? existing?.chapter ?? 'General', 'chapter', 200), q: str(b.q ?? existing?.q, 'question', 4000),
      options: opts, answer, explanation: clean(b.explanation ?? existing?.explanation, 4000) || null,
      difficulty: ['Easy', 'Medium', 'Hard'].includes(b.difficulty) ? b.difficulty : (existing?.difficulty || 'Medium'),
      passage: (b.passage ?? existing?.passage) ? String(b.passage ?? existing.passage).slice(0, 20000) : null,
      image: (b.image ?? existing?.image) ? String(b.image ?? existing.image).slice(0, 200000) : null,
    };
  }
  function ensureChapter(q) { db.prepare('INSERT OR IGNORE INTO chapters(subject,grade,year,region,name) VALUES(?,?,?,?,?)').run(q.subject, q.grade, q.year, q.region, q.chapter); }

  r.add('GET', '/api/admin/questions', async ctx => {
    requireAdmin(ctx);
    const where = []; const args = [];
    for (const k of ['subject', 'grade', 'year', 'region']) if (ctx.query[k]) { where.push(`${k} = ?`); args.push(clean(ctx.query[k], 40)); }
    if (ctx.query.unverified === '1') where.push('answer < 0');
    if (ctx.query.q) { where.push('q LIKE ?'); args.push('%' + clean(ctx.query.q, 60).replace(/[%_]/g, '') + '%'); }
    const page = Math.max(parseInt(ctx.query.page, 10) || 1, 1); const size = Math.min(Math.max(parseInt(ctx.query.pageSize, 10) || 50, 1), 200);
    const w = where.length ? 'WHERE ' + where.join(' AND ') : '';
    const total = db.prepare(`SELECT COUNT(*) AS n FROM questions ${w}`).get(...args).n;
    const rows = db.prepare(`SELECT * FROM questions ${w} ORDER BY id LIMIT ? OFFSET ?`).all(...args, size, (page - 1) * size).map(parseQuestion);
    return { questions: rows, total, page };
  });

  r.add('POST', '/api/admin/questions', async ctx => {
    const admin = requireAdmin(ctx);
    const q = readQuestionBody(ctx.body);
    const hash = questionHash(q);
    if (db.prepare('SELECT 1 FROM questions WHERE content_hash = ?').get(hash)) throw new HttpError(409, 'This exact question already exists.');
    const info = tx(() => {
      ensureChapter(q);
      const i = db.prepare('INSERT INTO questions(subject,grade,year,region,chapter,q,options,answer,explanation,difficulty,passage,image,origin,content_hash,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
        .run(q.subject, q.grade, q.year, q.region, q.chapter, q.q, JSON.stringify(q.options), q.answer, q.explanation, q.difficulty, q.passage, q.image, 'admin', hash, nowIso(), nowIso());
      recomputeFreeFlags(); bumpContentVersion();
      return i;
    });
    audit(admin.id, 'question_created', `#${info.lastInsertRowid}`, ctx.ip);
    return { status: 201, body: { id: Number(info.lastInsertRowid) } };
  });

  r.add('PUT', '/api/admin/questions/:id', async ctx => {
    const admin = requireAdmin(ctx);
    const existing = db.prepare('SELECT * FROM questions WHERE id = ?').get(ctx.params.id);
    if (!existing) throw new HttpError(404, 'Question not found.');
    const q = readQuestionBody(ctx.body, existing);
    const hash = questionHash(q);
    const clash = db.prepare('SELECT id FROM questions WHERE content_hash = ? AND id != ?').get(hash, existing.id);
    if (clash) throw new HttpError(409, `Another question (#${clash.id}) is identical.`);
    tx(() => {
      ensureChapter(q);
      db.prepare('UPDATE questions SET subject=?,grade=?,year=?,region=?,chapter=?,q=?,options=?,answer=?,explanation=?,difficulty=?,passage=?,image=?,content_hash=?,updated_at=? WHERE id=?')
        .run(q.subject, q.grade, q.year, q.region, q.chapter, q.q, JSON.stringify(q.options), q.answer, q.explanation, q.difficulty, q.passage, q.image, hash, nowIso(), existing.id);
      recomputeFreeFlags(); bumpContentVersion();
    });
    audit(admin.id, 'question_updated', `#${existing.id}`, ctx.ip);
    return { ok: true };
  });

  r.add('DELETE', '/api/admin/questions/:id', async ctx => {
    const admin = requireAdmin(ctx);
    const res = tx(() => { const d = db.prepare('DELETE FROM questions WHERE id = ?').run(ctx.params.id); recomputeFreeFlags(); bumpContentVersion(); return d; });
    if (!res.changes) throw new HttpError(404, 'Question not found.');
    audit(admin.id, 'question_deleted', `#${ctx.params.id}`, ctx.ip);
    return { ok: true };
  });

  return r;
}

module.exports = { buildRouter, userView, authenticate };
