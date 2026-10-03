'use strict';
const http = require('http');
const { config } = require('./config');
const { db } = require('./db');
const { hashPassword, normalizePhone, rateLimit } = require('./security');
const { HttpError, send, readJson, applyCors, clientIp } = require('./http');
const { buildRouter } = require('./routes');
const fs = require('fs');
const path = require('path');

const PAGES = { '/admin': 'admin/index.html', '/privacy': 'public/privacy.html', '/delete-account': 'public/delete-account.html' };
const PAGE_CSP = "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' blob: data:; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'";
function renderPage(rel) {
  const esc = v => String(v).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const html = fs.readFileSync(path.join(__dirname, '..', rel), 'utf8');
  return Buffer.from(html
    .replace(/\{\{APP_NAME\}\}/g, esc(config.legal.appName)).replace(/\{\{DEVELOPER\}\}/g, esc(config.legal.developer || config.legal.appName))
    .replace(/\{\{EMAIL\}\}/g, esc(config.legal.email || '(set CONTACT_EMAIL)')).replace(/\{\{TELEGRAM\}\}/g, esc(config.support.telegram || ''))
    .replace(/\{\{UPDATED\}\}/g, new Date().toISOString().slice(0, 10)));
}

function bootstrapAdmin() {
  const phone = normalizePhone(config.adminPhone);
  if (!phone || !config.adminPassword) return;
  const existing = db.prepare('SELECT * FROM users WHERE phone = ?').get(phone);
  if (existing) {
    if (existing.role !== 'admin') { db.prepare("UPDATE users SET role = 'admin' WHERE id = ?").run(existing.id); console.log('[admin] promoted existing account to admin:', phone); }
    return;
  }
  const now = new Date().toISOString();
  db.prepare("INSERT INTO users(phone,first_name,last_name,pass_hash,role,grade,region,created_at) VALUES(?,?,?,?,?,?,?,?)")
    .run(phone, config.adminName, '', hashPassword(config.adminPassword), 'admin', 'both', 'sidama', now);
  console.log('[admin] created admin account:', phone);
}

function createApp() {
  bootstrapAdmin();
  const router = buildRouter();

  return http.createServer(async (req, res) => {
    const started = Date.now();
    const ip = clientIp(req);
    let status = 500;
    try {
      applyCors(req, res);
      if (req.method === 'OPTIONS') { status = 204; res.writeHead(204, { 'Cache-Control': 'no-store' }); return res.end(); }

      const g = rateLimit('global:' + ip, 600, 60_000);
      if (!g.allowed) throw new HttpError(429, 'Too many requests.', { retryAfter: g.retryAfter });

      const url = new URL(req.url, 'http://localhost');
      const pageKey = url.pathname.replace(/\/+$/, '') || '/';
      if (req.method === 'GET' && PAGES[pageKey]) { status = 200; return send(res, 200, renderPage(PAGES[pageKey]), { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': PAGE_CSP }); }
      const m = router.match(req.method, url.pathname);
      if (!m.handler) throw new HttpError(m.pathMatched ? 405 : 404, m.pathMatched ? 'Method not allowed.' : 'Not found.');

      const body = await readJson(req);
      const ctx = { req, res, ip, params: m.params, query: Object.fromEntries(url.searchParams), body, user: null };
      const out = await m.handler(ctx);
      if (out && out.raw) { status = 200; return send(res, 200, out.raw, out.headers); }
      if (out && out.status && out.body !== undefined) { status = out.status; return send(res, out.status, out.body); }
      status = 200; return send(res, 200, out);
    } catch (e) {
      if (e instanceof HttpError) {
        status = e.status;
        return send(res, e.status, { error: e.message }, e.extra && e.extra.retryAfter ? { 'Retry-After': String(e.extra.retryAfter) } : {});
      }
      console.error('[error]', req.method, req.url, e && e.stack || e);
      return send(res, 500, { error: 'Something went wrong on the server.' });
    } finally {
      if (config.isProd || process.env.LOG_REQUESTS) console.log(JSON.stringify({ t: new Date().toISOString(), m: req.method, p: String(req.url).split('?')[0], s: status, ms: Date.now() - started, ip }));
    }
  });
}

module.exports = { createApp };
