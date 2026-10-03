'use strict';
/*
 * Import exam content from data/content.json into the database.
 *
 *   npm run import                 -> adds anything new, never touches questions you edited
 *   npm run import -- --replace    -> deletes previously imported questions first, then re-imports
 *   npm run import -- path/to/other.json
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { config } = require('../src/config');
const { db, tx, bumpContentVersion, recomputeFreeFlags } = require('../src/db');

const args = process.argv.slice(2);
const replace = args.includes('--replace');
const file = path.resolve(args.find(a => !a.startsWith('--')) || path.join(__dirname, '..', 'data', 'content.json'));
if (!fs.existsSync(file)) { console.error('File not found:', file); process.exit(1); }

const content = JSON.parse(fs.readFileSync(file, 'utf8'));
const now = new Date().toISOString();
const hashOf = q => crypto.createHash('sha1').update([q.subject, q.grade, q.year, q.region, q.q, q.options.join('\u241f')].join('\u241e')).digest('hex');

let added = 0, skipped = 0, invalid = 0;
tx(() => {
  if (replace) db.exec("DELETE FROM questions WHERE origin = 'import'");

  const upSubject = db.prepare('INSERT INTO subjects(id,name,icon,icon2,gradient,grades) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name, icon=excluded.icon, icon2=excluded.icon2, gradient=excluded.gradient, grades=excluded.grades');
  for (const s of content.subjects || []) upSubject.run(s.id, s.name, s.icon || null, s.icon2 || null, s.gradient || null, s.grades ? JSON.stringify(s.grades) : null);

  const insChapter = db.prepare('INSERT OR IGNORE INTO chapters(subject,grade,year,region,name) VALUES(?,?,?,?,?)');
  for (const c of content.chapters || []) insChapter.run(c.subject, c.grade, c.year, c.region || 'sidama', c.name);

  const insQ = db.prepare('INSERT OR IGNORE INTO questions(subject,grade,year,region,chapter,q,options,answer,explanation,difficulty,passage,image,origin,content_hash,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)');
  for (const raw of content.questions || []) {
    const q = { ...raw, region: raw.region || 'sidama' };
    if (!q.subject || !q.grade || !q.year || !q.q || !Array.isArray(q.options) || q.options.length < 2 || !(q.answer >= -1 && q.answer < q.options.length)) { invalid++; continue; }
    const res = insQ.run(q.subject, q.grade, q.year, q.region, q.chapter || 'General', q.q, JSON.stringify(q.options), q.answer, q.explanation || null, q.difficulty || 'Medium', q.passage || null, q.image || null, 'import', hashOf(q), now, now);
    if (res.changes) added++; else skipped++;
  }

  const insBook = db.prepare('INSERT OR IGNORE INTO books(subject,grade,title,file) VALUES(?,?,?,?)');
  for (const b of content.books || []) insBook.run(b.subject, b.grade, b.title, b.file);
  const insVideo = db.prepare('INSERT OR IGNORE INTO videos(subject,grade,title,url) VALUES(?,?,?,?)');
  for (const v of content.videos || []) insVideo.run(v.subject, v.grade, v.title, v.url);

  recomputeFreeFlags(config.freeQuestions);
  bumpContentVersion();
});

const total = db.prepare('SELECT COUNT(*) AS n FROM questions').get().n;
const unverified = db.prepare('SELECT COUNT(*) AS n FROM questions WHERE answer < 0').get().n;
console.log(`Import finished: ${added} added, ${skipped} already present, ${invalid} invalid. Database now has ${total} questions (${unverified} still need a verified answer).`);
