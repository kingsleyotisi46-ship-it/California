'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { Client } = require('pg');
async function main() {
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required');
  const client = new Client({ connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL.includes('localhost') ? false : { rejectUnauthorized: true } });
  await client.connect();
  try {
    await client.query('SELECT pg_advisory_lock($1)', [724061023]);
    await client.query('CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())');
    const dir = path.join(__dirname, '..', 'migrations');
    const files = fs.readdirSync(dir).filter(n => /^\d+_[a-z0-9_]+\.sql$/.test(n)).sort();
    for (const name of files) {
      if ((await client.query('SELECT 1 FROM schema_migrations WHERE name=$1', [name])).rowCount) continue;
      await client.query('BEGIN');
      try {
        await client.query(fs.readFileSync(path.join(dir, name), 'utf8'));
        await client.query('INSERT INTO schema_migrations(name) VALUES($1)', [name]);
        await client.query('COMMIT');
        console.log('Applied migration: ' + name);
      } catch (e) { await client.query('ROLLBACK'); throw e; }
    }
  } finally {
    await client.query('SELECT pg_advisory_unlock($1)', [724061023]).catch(() => {});
    await client.end();
  }
}
main().catch(e => { console.error('Migration failed:', e.message); process.exitCode = 1; });