'use strict';
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const { config } = require('./config');

fs.mkdirSync(config.dataDir, { recursive: true });
fs.mkdirSync(path.join(config.uploadDir, 'payments'), { recursive: true });

const dbFile = process.env.DB_FILE || path.join(config.dataDir, 'ethio-exam.sqlite');
const db = new DatabaseSync(dbFile);
db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000; PRAGMA synchronous = NORMAL;');

const SCHEMA_VERSION = 1;
db.exec(`
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  phone         TEXT NOT NULL UNIQUE,
  first_name    TEXT NOT NULL DEFAULT '',
  last_name     TEXT NOT NULL DEFAULT '',
  pass_hash     TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'student' CHECK (role IN ('student','admin')),
  grade         TEXT NOT NULL DEFAULT '8' CHECK (grade IN ('6','8','both')),
  region        TEXT,
  token_version INTEGER NOT NULL DEFAULT 0,
  created_at    TEXT NOT NULL,
  last_login_at TEXT
);

CREATE TABLE IF NOT EXISTS premium (
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  grade      TEXT NOT NULL CHECK (grade IN ('6','8')),
  expires_at TEXT NOT NULL,
  PRIMARY KEY (user_id, grade)
);

CREATE TABLE IF NOT EXISTS payments (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  plan            TEXT NOT NULL,
  amount          INTEGER NOT NULL,
  method          TEXT NOT NULL,
  reference       TEXT,
  screenshot_file TEXT NOT NULL,
  screenshot_hash TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected')),
  flag            TEXT,
  note            TEXT,
  created_at      TEXT NOT NULL,
  reviewed_at     TEXT,
  reviewed_by     INTEGER REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_payments_status ON payments(status, created_at);
CREATE INDEX IF NOT EXISTS idx_payments_user ON payments(user_id);
CREATE INDEX IF NOT EXISTS idx_payments_hash ON payments(screenshot_hash);

CREATE TABLE IF NOT EXISTS subjects (
  id       TEXT PRIMARY KEY,
  name     TEXT NOT NULL,
  icon     TEXT,
  icon2    TEXT,
  gradient TEXT,
  grades   TEXT
);

CREATE TABLE IF NOT EXISTS chapters (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  subject TEXT NOT NULL,
  grade   TEXT NOT NULL,
  year    TEXT NOT NULL,
  region  TEXT NOT NULL DEFAULT 'sidama',
  name    TEXT NOT NULL,
  UNIQUE (subject, grade, year, region, name)
);

CREATE TABLE IF NOT EXISTS questions (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  subject      TEXT NOT NULL,
  grade        TEXT NOT NULL,
  year         TEXT NOT NULL,
  region       TEXT NOT NULL DEFAULT 'sidama',
  chapter      TEXT NOT NULL DEFAULT 'General',
  q            TEXT NOT NULL,
  options      TEXT NOT NULL,
  answer       INTEGER NOT NULL DEFAULT -1,
  explanation  TEXT,
  difficulty   TEXT NOT NULL DEFAULT 'Medium',
  passage      TEXT,
  image        TEXT,
  is_free      INTEGER NOT NULL DEFAULT 0,
  origin       TEXT NOT NULL DEFAULT 'admin',
  content_hash TEXT NOT NULL UNIQUE,
  created_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_q_exam ON questions(subject, grade, year, region, id);
CREATE INDEX IF NOT EXISTS idx_q_free ON questions(is_free);

CREATE TABLE IF NOT EXISTS books  (id INTEGER PRIMARY KEY AUTOINCREMENT, subject TEXT NOT NULL, grade TEXT NOT NULL, title TEXT NOT NULL, file TEXT NOT NULL, UNIQUE(subject, grade, file));
CREATE TABLE IF NOT EXISTS videos (id INTEGER PRIMARY KEY AUTOINCREMENT, subject TEXT NOT NULL, grade TEXT NOT NULL, title TEXT NOT NULL, url  TEXT NOT NULL, UNIQUE(subject, grade, url));

CREATE TABLE IF NOT EXISTS history (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  grade          TEXT NOT NULL,
  subject        TEXT NOT NULL,
  year           TEXT NOT NULL,
  mode           TEXT NOT NULL,
  total          INTEGER NOT NULL,
  answered       INTEGER NOT NULL,
  correct        INTEGER NOT NULL,
  wrong          INTEGER NOT NULL,
  percentage     INTEGER NOT NULL,
  time_taken_sec INTEGER NOT NULL DEFAULT 0,
  detail         TEXT,
  created_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_history_user ON history(user_id, created_at);

CREATE TABLE IF NOT EXISTS audit_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER,
  action     TEXT NOT NULL,
  detail     TEXT,
  ip         TEXT,
  created_at TEXT NOT NULL
);
`);

const getMeta = db.prepare('SELECT value FROM meta WHERE key = ?');
const setMeta = db.prepare('INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value');
if (!getMeta.get('schema_version')) setMeta.run('schema_version', String(SCHEMA_VERSION));
if (!getMeta.get('content_version')) setMeta.run('content_version', '1');

function bumpContentVersion() {
  const v = Number(getMeta.get('content_version').value) + 1;
  setMeta.run('content_version', String(v));
  return v;
}
function contentVersion() { return Number(getMeta.get('content_version').value); }

function tx(fn) {
  db.exec('BEGIN IMMEDIATE');
  try { const r = fn(); db.exec('COMMIT'); return r; }
  catch (e) { try { db.exec('ROLLBACK'); } catch (_) {} throw e; }
}

// Recalculate which questions are free: the first N (by id) of each exam (subject+grade+year+region).
function recomputeFreeFlags(n = config.freeQuestions) {
  db.exec('UPDATE questions SET is_free = 0');
  db.prepare(`
    UPDATE questions SET is_free = 1 WHERE id IN (
      SELECT id FROM (
        SELECT id, ROW_NUMBER() OVER (PARTITION BY subject, grade, year, region ORDER BY id) AS rn FROM questions
      ) WHERE rn <= ?
    )`).run(n);
}

module.exports = { db, tx, bumpContentVersion, contentVersion, recomputeFreeFlags, dbFile };
