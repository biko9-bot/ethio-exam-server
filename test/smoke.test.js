'use strict';
/* End-to-end test: starts the real server on a temporary database and exercises every important flow. */
const fs = require('fs');
const os = require('os');
const path = require('path');
const assert = require('assert');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ethio-test-'));
Object.assign(process.env, {
  DB_FILE: path.join(tmp, 'test.sqlite'), DATA_DIR: tmp, UPLOAD_DIR: path.join(tmp, 'uploads'),
  JWT_SECRET: 'test-secret-test-secret-test-secret-123456', ADMIN_PHONE: '0910790995', ADMIN_PASSWORD: 'AdminPass#2026',
  CBE_ACCOUNT: '1000123456789', CBE_HOLDER: 'Test Holder', TELEBIRR_ACCOUNT: '0911000000', TELEBIRR_HOLDER: 'Test Holder',
  FREE_QUESTIONS_PER_EXAM: '5', NODE_ENV: 'test',
});

const { createApp } = require('../src/app');
const { db } = require('../src/db');

// PNG 1x1
const PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==';
const PNG2 = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAIAAAABCAYAAAD0In+KAAAAD0lEQVR42mNkYGD4z8DAAAAEBAEAxL2cBAAAAABJRU5ErkJggg==';

let passed = 0;
const results = [];
async function test(name, fn) {
  try { await fn(); passed++; results.push('  ok   ' + name); }
  catch (e) { results.push('  FAIL ' + name + '\n       ' + (e.stack || e).toString().split('\n').slice(0, 4).join('\n       ')); process.exitCode = 1; }
}

(async () => {
  const server = createApp();
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + server.address().port;
  const call = async (method, url, { token, body, headers } = {}) => {
    const res = await fetch(base + url, { method, headers: { ...(body ? { 'Content-Type': 'application/json' } : {}), ...(token ? { Authorization: 'Bearer ' + token } : {}), ...headers }, body: body ? JSON.stringify(body) : undefined });
    const ct = res.headers.get('content-type') || '';
    return { status: res.status, headers: res.headers, data: ct.includes('json') ? await res.json() : Buffer.from(await res.arrayBuffer()) };
  };

  // seed a little content: 2 exams
  const now = new Date().toISOString();
  db.prepare("INSERT INTO subjects(id,name,icon,grades) VALUES('english','English','fa-book','null'),('maths8','Maths','fa-calc','[\"8\"]')").run();
  const insQ = db.prepare("INSERT INTO questions(subject,grade,year,region,chapter,q,options,answer,origin,content_hash,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)");
  for (let i = 1; i <= 12; i++) insQ.run('maths8', '8', '2018', 'sidama', i <= 6 ? 'Chapter 1' : 'Chapter 2', 'Q' + i + '?', JSON.stringify(['a', 'b', 'c', 'd']), i % 4, 'import', 'h8-' + i, now, now);
  for (let i = 1; i <= 8; i++) insQ.run('english', '6', '2018', 'sidama', 'Chapter 1', 'E' + i + '?', JSON.stringify(['a', 'b']), 0, 'import', 'h6-' + i, now, now);
  require('../src/db').recomputeFreeFlags(5);

  let student, adminToken, payId;

  await test('health endpoint works', async () => { const r = await call('GET', '/health'); assert.equal(r.status, 200); assert.equal(r.data.ok, true); });
  await test('unknown route is 404, wrong method is 405', async () => { assert.equal((await call('GET', '/nope')).status, 404); assert.equal((await call('GET', '/api/auth/login')).status, 405); });
  await test('security headers present', async () => { const r = await call('GET', '/health'); assert.equal(r.headers.get('x-content-type-options'), 'nosniff'); });
  await test('config exposes server-side prices and payment accounts', async () => {
    const r = await call('GET', '/api/config'); assert.equal(r.data.plans.find(p => p.id === 'both').price, 250);
    assert.equal(r.data.paymentMethods.length, 2); assert.equal(r.data.freeQuestionsPerExam, 5);
  });

  await test('register validates phone and password', async () => {
    assert.equal((await call('POST', '/api/auth/register', { body: { phone: '12345', password: 'secret1' } })).status, 400);
    assert.equal((await call('POST', '/api/auth/register', { body: { phone: '0911223344', password: '123' } })).status, 400);
  });
  await test('register + normalises +251 phone format', async () => {
    const r = await call('POST', '/api/auth/register', { body: { firstName: 'Abebe', lastName: 'Kebede', phone: '+251911223344', password: 'secret1', grade: '8' } });
    assert.equal(r.status, 201); assert.equal(r.data.user.phone, '0911223344'); assert.equal(r.data.user.role, 'student');
    assert.ok(!('pass_hash' in r.data.user) && !JSON.stringify(r.data).includes('scrypt'));
    student = r.data;
  });
  await test('duplicate registration is rejected (same number, different format)', async () => {
    assert.equal((await call('POST', '/api/auth/register', { body: { phone: '0911223344', password: 'secret1' } })).status, 409);
    assert.equal((await call('POST', '/api/auth/register', { body: { phone: '911223344', password: 'secret1' } })).status, 409);
  });
  await test('nobody can become admin by registering the admin phone', async () => {
    assert.equal((await call('POST', '/api/auth/register', { body: { phone: '0910790995', password: 'secret1' } })).status, 409);
    const r = await call('POST', '/api/auth/register', { body: { phone: '0922000000', password: 'secret1', role: 'admin', premium: true } });
    assert.equal(r.data.user.role, 'student'); assert.equal(r.data.user.premium['8'].active, false);
  });
  await test('login: wrong password 401, right password 200', async () => {
    assert.equal((await call('POST', '/api/auth/login', { body: { phone: '0911223344', password: 'wrong' } })).status, 401);
    assert.equal((await call('POST', '/api/auth/login', { body: { phone: '0911223344', password: 'secret1' } })).status, 200);
  });
  await test('/api/me needs a valid token; tampered token rejected', async () => {
    assert.equal((await call('GET', '/api/me')).status, 401);
    assert.equal((await call('GET', '/api/me', { token: student.token + 'x' })).status, 401);
    assert.equal((await call('GET', '/api/me', { token: student.token })).status, 200);
  });
  await test('region can be saved', async () => {
    const r = await call('PATCH', '/api/me', { token: student.token, body: { region: 'sidama' } }); assert.equal(r.data.user.region, 'sidama');
    assert.equal((await call('PATCH', '/api/me', { token: student.token, body: { region: '../x' } })).status, 400);
  });

  await test('free user only receives the free questions of an exam', async () => {
    const r = await call('GET', '/api/questions?grade=8&subject=maths8&year=2018', { token: student.token });
    assert.equal(r.status, 200); assert.equal(r.data.questions.length, 5); assert.equal(r.data.total, 12); assert.equal(r.data.locked, true); assert.equal(r.data.lockedCount, 7);
  });
  await test('free user cannot get locked questions by filtering chapter / random', async () => {
    const c2 = await call('GET', '/api/questions?grade=8&subject=maths8&year=2018&chapter=Chapter%202', { token: student.token });
    assert.equal(c2.data.questions.length, 0);
    const rnd = await call('GET', '/api/questions?grade=8&subject=maths8&random=1&count=50', { token: student.token });
    assert.equal(rnd.data.questions.length, 5);
  });
  await test('questions require login', async () => { assert.equal((await call('GET', '/api/questions?grade=8&subject=maths8')).status, 401); });
  await test('manifest lists exams and chapters with counts', async () => {
    const r = await call('GET', '/api/content/manifest?region=sidama', { token: student.token });
    assert.equal(r.status, 200); assert.ok(r.data.exams.find(e => e.subject === 'maths8' && e.count === 12 && e.freeCount === 5)); assert.equal(r.data.chapters.filter(c => c.subject === 'maths8').length, 2);
  });

  await test('payment: price is decided by the server, not the client', async () => {
    const r = await call('POST', '/api/payments', { token: student.token, body: { plan: '8', method: 'cbe', screenshot: PNG, amount: 1, reference: 'FT123' } });
    assert.equal(r.status, 201); assert.equal(r.data.amount, 150); payId = r.data.id;
  });
  await test('payment: bad plan / method / non-image rejected', async () => {
    assert.equal((await call('POST', '/api/payments', { token: student.token, body: { plan: 'gold', method: 'cbe', screenshot: PNG } })).status, 400);
    assert.equal((await call('POST', '/api/payments', { token: student.token, body: { plan: '8', method: 'bitcoin', screenshot: PNG } })).status, 400);
    assert.equal((await call('POST', '/api/payments', { token: student.token, body: { plan: '8', method: 'cbe', screenshot: 'data:image/png;base64,' + Buffer.from('<script>alert(1)</script>').toString('base64') } })).status, 400);
    assert.equal((await call('POST', '/api/payments', { token: student.token, body: { plan: '8', method: 'cbe', screenshot: 'data:text/html;base64,PGgxPg==' } })).status, 400);
  });
  await test('payment alone does NOT unlock premium', async () => {
    const r = await call('GET', '/api/me', { token: student.token }); assert.equal(r.data.user.premium['8'].active, false);
  });
  await test('students cannot reach admin endpoints', async () => {
    for (const [m, u] of [['GET', '/api/admin/stats'], ['GET', '/api/admin/payments'], ['POST', '/api/admin/payments/' + payId + '/approve'], ['GET', '/api/admin/users']]) assert.equal((await call(m, u, { token: student.token, body: m === 'POST' ? {} : undefined })).status, 403);
    assert.equal((await call('GET', '/api/admin/stats')).status, 401);
  });
  await test('admin can log in', async () => {
    const r = await call('POST', '/api/auth/login', { body: { phone: '0910790995', password: 'AdminPass#2026' } }); assert.equal(r.status, 200); assert.equal(r.data.user.role, 'admin'); adminToken = r.data.token;
  });
  await test('admin sees pending payment and its screenshot', async () => {
    const r = await call('GET', '/api/admin/payments?status=pending', { token: adminToken }); assert.equal(r.data.payments.length, 1); assert.equal(r.data.payments[0].phone, '0911223344');
    const img = await call('GET', `/api/admin/payments/${payId}/screenshot`, { token: adminToken }); assert.equal(img.status, 200); assert.equal(img.headers.get('content-type'), 'image/png');
  });
  await test('same screenshot re-used is flagged for the admin', async () => {
    const other = await call('POST', '/api/auth/register', { body: { phone: '0933000000', password: 'secret1' } });
    await call('POST', '/api/payments', { token: other.data.token, body: { plan: '6', method: 'telebirr', screenshot: PNG } });
    const r = await call('GET', '/api/admin/payments?status=pending', { token: adminToken });
    assert.ok(r.data.payments.some(p => (p.flag || '').includes('duplicate_screenshot')));
    for (const p of r.data.payments.filter(p => p.id !== payId)) await call('POST', `/api/admin/payments/${p.id}/reject`, { token: adminToken, body: { note: 'duplicate' } });
  });
  await test('admin approves -> premium unlocked for that grade only, all questions returned', async () => {
    const a = await call('POST', `/api/admin/payments/${payId}/approve`, { token: adminToken, body: {} }); assert.equal(a.status, 200);
    const me = await call('GET', '/api/me', { token: student.token }); assert.equal(me.data.user.premium['8'].active, true); assert.equal(me.data.user.premium['6'].active, false);
    const qs = await call('GET', '/api/questions?grade=8&subject=maths8&year=2018', { token: student.token }); assert.equal(qs.data.questions.length, 12); assert.equal(qs.data.locked, false);
    const g6 = await call('GET', '/api/questions?grade=6&subject=english&year=2018', { token: student.token }); assert.equal(g6.data.questions.length, 5);
  });
  await test('a payment cannot be approved twice', async () => { assert.equal((await call('POST', `/api/admin/payments/${payId}/approve`, { token: adminToken, body: {} })).status, 409); });
  await test('renewing extends from the current expiry (no lost days)', async () => {
    const before = (await call('GET', '/api/me', { token: student.token })).data.user.premium['8'].expiry;
    const p = await call('POST', '/api/payments', { token: student.token, body: { plan: '8', method: 'cbe', screenshot: PNG2 } });
    await call('POST', `/api/admin/payments/${p.data.id}/approve`, { token: adminToken, body: {} });
    const after = (await call('GET', '/api/me', { token: student.token })).data.user.premium['8'].expiry;
    const days = Math.round((new Date(after) - new Date(before)) / 86400000); assert.equal(days, 365);
  });

  await test('exercise history is saved and returned (percentage computed on server)', async () => {
    const r = await call('POST', '/api/history', { token: student.token, body: { grade: '8', subject: 'maths8', year: '2018', mode: 'year', total: 10, answered: 10, correct: 7, wrong: 3, percentage: 100, timeTakenSec: 120 } });
    assert.equal(r.status, 201); assert.equal(r.data.percentage, 70);
    assert.equal((await call('POST', '/api/history', { token: student.token, body: { grade: '8', subject: 'maths8', year: '2018', mode: 'year', total: 10, answered: 20, correct: 7, wrong: 3 } })).status, 400);
    assert.equal((await call('GET', '/api/history?grade=8', { token: student.token })).data.history.length, 1);
  });

  await test('admin can add, edit and delete questions; duplicates and bad data rejected', async () => {
    const good = { subject: 'maths8', grade: '8', year: '2018', chapter: 'Chapter 3', q: 'New question?', options: ['1', '2', '3', '4'], answer: 2 };
    const c = await call('POST', '/api/admin/questions', { token: adminToken, body: good }); assert.equal(c.status, 201);
    assert.equal((await call('POST', '/api/admin/questions', { token: adminToken, body: good })).status, 409);
    assert.equal((await call('POST', '/api/admin/questions', { token: adminToken, body: { ...good, q: 'Other?', options: ['1', '1', '3'] } })).status, 400);
    assert.equal((await call('POST', '/api/admin/questions', { token: adminToken, body: { ...good, q: 'Other?', answer: 9 } })).status, 400);
    assert.equal((await call('POST', '/api/admin/questions', { token: adminToken, body: { ...good, q: 'Other?', subject: 'nope' } })).status, 400);
    assert.equal((await call('PUT', `/api/admin/questions/${c.data.id}`, { token: adminToken, body: { answer: 1 } })).status, 200);
    assert.equal((await call('DELETE', `/api/admin/questions/${c.data.id}`, { token: adminToken })).status, 200);
    assert.equal((await call('DELETE', `/api/admin/questions/${c.data.id}`, { token: adminToken })).status, 404);
  });
  await test('content version increases when content changes', async () => {
    const v1 = (await call('GET', '/api/config')).data.contentVersion;
    await call('POST', '/api/admin/questions', { token: adminToken, body: { subject: 'maths8', grade: '8', year: '2018', chapter: 'Chapter 3', q: 'Another?', options: ['1', '2'], answer: 0 } });
    assert.ok((await call('GET', '/api/config')).data.contentVersion > v1);
  });
  await test('stats endpoint counts correctly', async () => {
    const r = await call('GET', '/api/admin/stats', { token: adminToken }); assert.ok(r.data.users >= 3); assert.equal(r.data.premiumUsers, 1); assert.equal(r.data.approvedRevenueETB, 300);
  });
  await test('admin can manually grant and revoke premium', async () => {
    const list = (await call('GET', '/api/admin/users?q=0922', { token: adminToken })).data.users; const id = list[0].id;
    assert.equal((await call('POST', `/api/admin/users/${id}/premium`, { token: adminToken, body: { grade: 'both', days: 30 } })).status, 200);
    let users = (await call('GET', '/api/admin/users?q=0922', { token: adminToken })).data.users; assert.equal(users[0].premium['6'].active, true);
    await call('POST', `/api/admin/users/${id}/premium`, { token: adminToken, body: { grade: 'both', revoke: true } });
    users = (await call('GET', '/api/admin/users?q=0922', { token: adminToken })).data.users; assert.equal(users[0].premium['6'].active, false);
  });

  await test('password change invalidates old tokens', async () => {
    const reg = await call('POST', '/api/auth/register', { body: { phone: '0944000000', password: 'oldpass1' } });
    const ch = await call('POST', '/api/me/password', { token: reg.data.token, body: { oldPassword: 'oldpass1', newPassword: 'newpass22' } }); assert.equal(ch.status, 200);
    assert.equal((await call('GET', '/api/me', { token: reg.data.token })).status, 401);
    assert.equal((await call('GET', '/api/me', { token: ch.data.token })).status, 200);
    assert.equal((await call('POST', '/api/auth/login', { body: { phone: '0944000000', password: 'newpass22' } })).status, 200);
  });
  await test('CORS: allowed origin echoed, unknown origin gets no CORS header', async () => {
    const ok = await call('OPTIONS', '/api/me', { headers: { Origin: 'https://localhost' } }); assert.equal(ok.status, 204); assert.equal(ok.headers.get('access-control-allow-origin'), 'https://localhost');
    const bad = await call('OPTIONS', '/api/me', { headers: { Origin: 'https://evil.example' } }); assert.equal(bad.headers.get('access-control-allow-origin'), null);
  });
  await test('invalid JSON / wrong content type handled', async () => {
    const res = await fetch(base + '/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{bad' }); assert.equal(res.status, 400);
    const res2 = await fetch(base + '/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: 'x' }); assert.equal(res2.status, 415);
  });
  await test('SQL injection strings are treated as plain text', async () => {
    const r = await call('POST', '/api/auth/login', { body: { phone: "0911223344' OR '1'='1", password: "' OR '1'='1" } }); assert.ok([400, 401].includes(r.status));
    const q = await call('GET', "/api/questions?grade=8&subject=" + encodeURIComponent("maths8' OR 1=1 --"), { token: student.token }); assert.equal(q.data.questions.length, 0);
  });
  await test('brute force: login is rate limited per account', async () => {
    let last; for (let i = 0; i < 12; i++) last = await call('POST', '/api/auth/login', { body: { phone: '0955000000', password: 'guess' + i } });
    assert.equal(last.status, 429); assert.ok(last.headers.get('retry-after'));
  });


  await test('legal + admin pages are served (HTML with their own CSP)', async () => {
    for (const u of ['/privacy', '/delete-account', '/admin']) {
      const r = await fetch(base + u); assert.equal(r.status, 200); assert.ok((r.headers.get('content-type') || '').includes('text/html'));
      const html = await r.text(); assert.ok(!html.includes('{{')); assert.ok(r.headers.get('content-security-policy').includes("frame-ancestors 'none'"));
    }
    const pr = await (await fetch(base + '/privacy')).text(); assert.ok(pr.includes('Ethio Ministry Exam'));
  });
  await test('account deletion: needs password, removes user, payments and screenshots', async () => {
    const reg = await call('POST', '/api/auth/register', { body: { phone: '0966000000', password: 'delete-me-1' } });
    const pay = await call('POST', '/api/payments', { token: reg.data.token, body: { plan: '6', method: 'cbe', screenshot: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAAXNSR0IArs4c6QAAAA1JREFUCNdjYPj/HwADAgH/Q1j2BwAAAABJRU5ErkJggg==' } });
    assert.equal(pay.status, 201);
    const files = fs.readdirSync(path.join(process.env.UPLOAD_DIR, 'payments')).length;
    const bad = await fetch(base + '/api/me', { method: 'DELETE', headers: { Authorization: 'Bearer ' + reg.data.token, 'X-Confirm-Password': 'nope' } }); assert.equal(bad.status, 401);
    const ok = await fetch(base + '/api/me', { method: 'DELETE', headers: { Authorization: 'Bearer ' + reg.data.token, 'X-Confirm-Password': 'delete-me-1' } }); assert.equal(ok.status, 200);
    assert.equal((await call('POST', '/api/auth/login', { body: { phone: '0966000000', password: 'delete-me-1' } })).status, 401);
    assert.equal(db.prepare('SELECT COUNT(*) n FROM payments WHERE user_id = ?').get(reg.data.user.id).n, 0);
    assert.equal(fs.readdirSync(path.join(process.env.UPLOAD_DIR, 'payments')).length, files - 1);
    const admin = await fetch(base + '/api/me', { method: 'DELETE', headers: { Authorization: 'Bearer ' + adminToken, 'X-Confirm-Password': 'AdminPass#2026' } }); assert.equal(admin.status, 403);
  });

  server.close();
  console.log('\n' + results.join('\n') + `\n\n${passed}/${results.length} tests passed`);
  fs.rmSync(tmp, { recursive: true, force: true });
  process.exit(process.exitCode || 0);
})();
