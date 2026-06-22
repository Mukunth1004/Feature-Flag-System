const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
require('dotenv').config({ path: require('path').join(__dirname, '../.env') });

const dbPath = path.resolve(__dirname, '..', process.env.DB_PATH || './data/flags.db');
const dbDir = path.dirname(dbPath);

if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const db = new Database(dbPath);

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS roles (
    id   INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT    NOT NULL UNIQUE
  );

  CREATE TABLE IF NOT EXISTS organizations (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL UNIQUE,
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL REFERENCES roles(name),
    org_id        INTEGER NOT NULL REFERENCES organizations(id),
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS feature_flags (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    key        TEXT    NOT NULL,
    enabled    INTEGER NOT NULL DEFAULT 0,
    org_id     INTEGER NOT NULL REFERENCES organizations(id),
    created_at TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(key, org_id)
  );
`);

// Seed roles
db.prepare(`INSERT OR IGNORE INTO roles (name) VALUES ('super_admin')`).run();
db.prepare(`INSERT OR IGNORE INTO roles (name) VALUES ('org_admin')`).run();
db.prepare(`INSERT OR IGNORE INTO roles (name) VALUES ('end_user')`).run();

module.exports = db;
