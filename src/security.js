'use strict';
const crypto = require('crypto');
const { config } = require('./config');

/* ---------- passwords (scrypt, built into Node — no native modules to compile) ---------- */
const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 64 };
function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, SCRYPT.keylen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p });
  return ['scrypt', SCRYPT.N, SCRYPT.r, SCRYPT.p, salt.toString('base64'), hash.toString('base64')].join('$');
}
function verifyPassword(password, stored) {
  try {
    const [alg, N, r, p, salt, hash] = String(stored).split('$');
    if (alg !== 'scrypt') return false;
    const expected = Buffer.from(hash, 'base64');
    const actual = crypto.scryptSync(password, Buffer.from(salt, 'base64'), expected.length, { N: +N, r: +r, p: +p });
    return crypto.timingSafeEqual(actual, expected);
  } catch (_) { return false; }
}
// Used to keep response time similar when the phone number does not exist.
const DUMMY_HASH = hashPassword('dummy-password-for-timing');

/* ---------- signed tokens (HS256 JWT) ---------- */
const b64u = b => Buffer.from(b).toString('base64url');
function signToken(payload, ttlSeconds = 60 * 60 * 24 * 60) {
  const now = Math.floor(Date.now() / 1000);
  const head = b64u(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = b64u(JSON.stringify({ ...payload, iat: now, exp: now + ttlSeconds }));
  const sig = crypto.createHmac('sha256', config.jwtSecret).update(head + '.' + body).digest('base64url');
  return head + '.' + body + '.' + sig;
}
function verifyToken(token) {
  try {
    const [head, body, sig] = String(token).split('.');
    if (!head || !body || !sig) return null;
    const expected = crypto.createHmac('sha256', config.jwtSecret).update(head + '.' + body).digest();
    const given = Buffer.from(sig, 'base64url');
    if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return null;
    const header = JSON.parse(Buffer.from(head, 'base64url').toString());
    if (header.alg !== 'HS256') return null;
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch (_) { return null; }
}

/* ---------- tiny in-memory rate limiter ---------- */
const buckets = new Map();
function rateLimit(key, max, windowMs) {
  const now = Date.now();
  let b = buckets.get(key);
  if (!b || b.reset < now) { b = { count: 0, reset: now + windowMs }; buckets.set(key, b); }
  b.count++;
  return { allowed: b.count <= max, retryAfter: Math.ceil((b.reset - now) / 1000) };
}
setInterval(() => { const now = Date.now(); for (const [k, b] of buckets) if (b.reset < now) buckets.delete(k); }, 60_000).unref();

/* ---------- input helpers ---------- */
// Accepts 09xxxxxxxx, 07xxxxxxxx, 9xxxxxxxx, +2519xxxxxxxx, 2519xxxxxxxx  ->  09xxxxxxxx / 07xxxxxxxx
function normalizePhone(input) {
  let s = String(input || '').replace(/[\s\-()]/g, '');
  if (s.startsWith('+251')) s = '0' + s.slice(4);
  else if (s.startsWith('251') && s.length === 12) s = '0' + s.slice(3);
  else if (/^[79]\d{8}$/.test(s)) s = '0' + s;
  return /^0[79]\d{8}$/.test(s) ? s : null;
}
const clean = (v, max) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, max);

module.exports = { hashPassword, verifyPassword, DUMMY_HASH, signToken, verifyToken, rateLimit, normalizePhone, clean };
