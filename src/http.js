'use strict';
const { config } = require('./config');

class HttpError extends Error {
  constructor(status, message, extra) { super(message); this.status = status; this.extra = extra; }
}

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Cache-Control': 'no-store',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
  'Cross-Origin-Resource-Policy': 'cross-origin',
};

function applyCors(req, res) {
  const origin = req.headers.origin;
  if (!origin) return true;
  if (config.allowedOrigins.includes('*') || config.allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Confirm-Password');
    res.setHeader('Access-Control-Max-Age', '600');
    return true;
  }
  return false;
}

function send(res, status, data, headers = {}) {
  const body = Buffer.isBuffer(data) ? data : Buffer.from(JSON.stringify(data));
  const type = Buffer.isBuffer(data) ? (headers['Content-Type'] || 'application/octet-stream') : 'application/json; charset=utf-8';
  res.writeHead(status, { ...SECURITY_HEADERS, ...headers, 'Content-Type': type, 'Content-Length': body.length });
  res.end(body);
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    if (['GET', 'HEAD', 'DELETE'].includes(req.method)) return resolve({});
    const type = String(req.headers['content-type'] || '');
    if (!type.includes('application/json')) return reject(new HttpError(415, 'Send JSON (Content-Type: application/json).'));
    let size = 0; const chunks = [];
    req.on('data', c => {
      size += c.length;
      if (size > config.maxBodyBytes) { reject(new HttpError(413, 'Request too large.')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!size) return resolve({});
      try { const v = JSON.parse(Buffer.concat(chunks).toString('utf8')); resolve(v && typeof v === 'object' ? v : {}); }
      catch (_) { reject(new HttpError(400, 'Invalid JSON.')); }
    });
    req.on('error', () => reject(new HttpError(400, 'Request error.')));
  });
}

function clientIp(req) {
  if (config.trustProxy) {
    const xf = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    if (xf) return xf;
  }
  return req.socket.remoteAddress || 'unknown';
}

class Router {
  constructor() { this.routes = []; }
  add(method, path, handler) {
    const keys = [];
    const re = new RegExp('^' + path.replace(/:([a-zA-Z]+)/g, (_, k) => { keys.push(k); return '([^/]+)'; }) + '/?$');
    this.routes.push({ method, re, keys, handler });
  }
  match(method, pathname) {
    let pathMatched = false;
    for (const r of this.routes) {
      const m = r.re.exec(pathname);
      if (!m) continue;
      pathMatched = true;
      if (r.method !== method) continue;
      const params = {};
      r.keys.forEach((k, i) => { params[k] = decodeURIComponent(m[i + 1]); });
      return { handler: r.handler, params };
    }
    return { handler: null, pathMatched };
  }
}

module.exports = { HttpError, send, readJson, applyCors, clientIp, Router };
