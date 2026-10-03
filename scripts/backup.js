'use strict';
/* Makes a safe copy of the database (and prunes old copies). Run daily from cron. */
const fs = require('fs');
const path = require('path');
const { config } = require('../src/config');
const { db } = require('../src/db');

const dir = path.resolve(config.dataDir, '..', 'backups');
fs.mkdirSync(dir, { recursive: true });
const stamp = new Date().toISOString().replace(/[:T]/g, '-').slice(0, 16);
const target = path.join(dir, `ethio-exam-${stamp}.sqlite`);
db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
db.exec(`VACUUM INTO '${target.replace(/'/g, "''")}'`);
console.log('Backup written:', target);

const keep = Number(process.env.BACKUP_KEEP || 14);
const files = fs.readdirSync(dir).filter(f => f.endsWith('.sqlite')).sort();
for (const f of files.slice(0, Math.max(files.length - keep, 0))) { fs.unlinkSync(path.join(dir, f)); console.log('Removed old backup:', f); }
