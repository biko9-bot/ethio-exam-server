'use strict';
const fs = require('fs');
const path = require('path');

// Minimal .env loader (no dependency needed).
(function loadEnv() {
  const file = path.join(__dirname, '..', '.env');
  if (!fs.existsSync(file)) return;
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    if (line.trim().startsWith('#')) continue;
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/i);
    if (!m) continue;
    let v = m[2];
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
    if (process.env[m[1]] === undefined) process.env[m[1]] = v;
  }
})();

const env = process.env;
const root = path.join(__dirname, '..');
const num = (v, d) => (v !== undefined && v !== '' && !Number.isNaN(Number(v)) ? Number(v) : d);

const config = {
  port: num(env.PORT, 3000),
  isProd: env.NODE_ENV === 'production',
  dataDir: path.resolve(root, env.DATA_DIR || './data'),
  uploadDir: path.resolve(root, env.UPLOAD_DIR || './uploads'),
  jwtSecret: env.JWT_SECRET || '',
  adminPhone: env.ADMIN_PHONE || '',
  adminPassword: env.ADMIN_PASSWORD || '',
  adminName: env.ADMIN_NAME || 'Admin',
  allowedOrigins: (env.ALLOWED_ORIGINS || 'https://localhost,http://localhost,capacitor://localhost')
    .split(',').map(s => s.trim()).filter(Boolean),
  trustProxy: env.TRUST_PROXY === '1',
  subscriptionDays: num(env.SUBSCRIPTION_DAYS, 365),
  freeQuestions: num(env.FREE_QUESTIONS_PER_EXAM, 5),
  plans: [
    { id: '6', label: 'Grade 6', price: num(env.PRICE_GRADE_6, 150), grades: ['6'] },
    { id: '8', label: 'Grade 8', price: num(env.PRICE_GRADE_8, 150), grades: ['8'] },
    { id: 'both', label: 'Both Grades', price: num(env.PRICE_BOTH, 250), grades: ['6', '8'] },
  ],
  paymentMethods: [
    { id: 'cbe', label: 'CBE', account: env.CBE_ACCOUNT || '', holder: env.CBE_HOLDER || '' },
    { id: 'telebirr', label: 'Telebirr', account: env.TELEBIRR_ACCOUNT || '', holder: env.TELEBIRR_HOLDER || '' },
  ],
  support: { phone: env.SUPPORT_PHONE || '', telegram: env.SUPPORT_TELEGRAM || '' },
  legal: { appName: env.APP_NAME || 'Ethio Ministry Exam', developer: env.DEVELOPER_NAME || '', email: env.CONTACT_EMAIL || '' },
  maxBodyBytes: 4 * 1024 * 1024,
  maxScreenshotBytes: 3 * 1024 * 1024,
};

function validate() {
  const problems = [];
  if (!config.jwtSecret || config.jwtSecret.length < 32 || /CHANGE_ME/.test(config.jwtSecret)) problems.push('JWT_SECRET must be a random string of at least 32 characters.');
  if (config.adminPhone && (!config.adminPassword || config.adminPassword.length < 8 || /CHANGE_ME/.test(config.adminPassword))) problems.push('ADMIN_PASSWORD must be at least 8 characters and not the example value.');
  if (config.isProd && !config.legal.email) problems.push('CONTACT_EMAIL must be set (it is shown on your privacy policy page, which Google Play requires).');
  return problems;
}

module.exports = { config, validate };
