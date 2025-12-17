import fs from 'node:fs/promises';
import path from 'node:path';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';

async function ensureDir(dirPath) {
  await fs.mkdir(dirPath, { recursive: true });
}

export async function openDatabase({ rootDir }) {
  const dbFile = process.env.DATABASE_PATH
    ? String(process.env.DATABASE_PATH)
    : path.join(rootDir, 'data', 'wled-presets.sqlite');

  await ensureDir(path.dirname(dbFile));

  const db = await open({
    filename: dbFile,
    driver: sqlite3.Database
  });

  await db.exec('PRAGMA foreign_keys = ON;');
  await db.exec('PRAGMA journal_mode = WAL;');

  await db.exec(`
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS admin_users (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS devices (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      host TEXT NOT NULL,
      port INTEGER NOT NULL DEFAULT 80,
      enabled INTEGER NOT NULL DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS public_presets (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS public_preset_mappings (
      publicPresetId TEXT NOT NULL,
      deviceId TEXT NOT NULL,
      presetId INTEGER NOT NULL,
      PRIMARY KEY (publicPresetId, deviceId),
      FOREIGN KEY (publicPresetId) REFERENCES public_presets(id) ON DELETE CASCADE,
      FOREIGN KEY (deviceId) REFERENCES devices(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS device_presets (
      deviceId TEXT NOT NULL,
      presetId INTEGER NOT NULL,
      name TEXT NOT NULL,
      PRIMARY KEY (deviceId, presetId),
      FOREIGN KEY (deviceId) REFERENCES devices(id) ON DELETE CASCADE
    );
  `);

  return db;
}

export async function countAdminUsers(db) {
  const row = await db.get('SELECT COUNT(*) AS c FROM admin_users');
  return Number(row?.c || 0);
}

export async function getAdminUserByUsername(db, username) {
  const u = String(username || '').trim();
  if (!u) return null;
  return await db.get('SELECT id, username, password_hash AS passwordHash FROM admin_users WHERE username = ?', [u]);
}

export async function getAdminUserById(db, id) {
  const v = String(id || '').trim();
  if (!v) return null;
  return await db.get('SELECT id, username FROM admin_users WHERE id = ?', [v]);
}

export async function createAdminUser(db, { id, username, passwordHash }) {
  const u = String(username || '').trim();
  const ph = String(passwordHash || '').trim();
  const i = String(id || '').trim();
  if (!i || !u || !ph) throw new Error('Invalid admin user');

  await db.run(
    `INSERT INTO admin_users(id, username, password_hash)
     VALUES(?, ?, ?)
     ON CONFLICT(username) DO NOTHING`,
    [i, u, ph]
  );
}

export async function getSetting(db, key, defaultValue = '') {
  const row = await db.get('SELECT value FROM settings WHERE key = ?', [key]);
  return row ? row.value : defaultValue;
}

export async function setSetting(db, key, value) {
  await db.run(
    'INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value',
    [key, String(value)]
  );
}

export async function getDevices(db) {
  const rows = await db.all('SELECT id, name, host, port, enabled FROM devices ORDER BY name COLLATE NOCASE');
  return rows.map((r) => ({
    id: r.id,
    name: r.name,
    host: r.host,
    port: r.port,
    enabled: Boolean(r.enabled)
  }));
}

export async function replaceDevices(db, devices) {
  await db.exec('BEGIN');
  try {
    // Get existing device IDs
    const existingRows = await db.all('SELECT id FROM devices');
    const existingIds = new Set(existingRows.map(r => r.id));
    const newIds = new Set(devices.map(d => d.id));
    
    // Delete devices that are no longer in the list
    // (ON DELETE CASCADE will clean up device_presets for removed devices only)
    for (const existingId of existingIds) {
      if (!newIds.has(existingId)) {
        await db.run('DELETE FROM devices WHERE id = ?', [existingId]);
      }
    }
    
    // Upsert devices
    for (const d of devices) {
      await db.run(
        `INSERT INTO devices(id, name, host, port, enabled) VALUES(?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET name=excluded.name, host=excluded.host, port=excluded.port, enabled=excluded.enabled`,
        [d.id, d.name, d.host, d.port ?? 80, d.enabled ? 1 : 0]
      );
    }
    await db.exec('COMMIT');
  } catch (e) {
    await db.exec('ROLLBACK');
    throw e;
  }
}

export async function getPublicPresetsWithMappings(db) {
  const presets = await db.all('SELECT id, name FROM public_presets ORDER BY name COLLATE NOCASE');
  const mappings = await db.all('SELECT publicPresetId, deviceId, presetId FROM public_preset_mappings');

  const byPresetId = new Map();
  for (const p of presets) {
    byPresetId.set(p.id, { id: p.id, name: p.name, devicePresets: {} });
  }

  for (const m of mappings) {
    const p = byPresetId.get(m.publicPresetId);
    if (!p) continue;
    p.devicePresets[m.deviceId] = Number(m.presetId);
  }

  return Array.from(byPresetId.values());
}

export async function replacePublicPresets(db, publicPresets, existingDeviceIds = null) {
  // If existingDeviceIds not provided, fetch from DB
  let validDeviceIds = existingDeviceIds;
  if (!validDeviceIds) {
    const devices = await db.all('SELECT id FROM devices');
    validDeviceIds = new Set(devices.map(d => d.id));
  } else if (!(validDeviceIds instanceof Set)) {
    validDeviceIds = new Set(validDeviceIds);
  }

  await db.exec('BEGIN');
  try {
    await db.exec('DELETE FROM public_preset_mappings');
    await db.exec('DELETE FROM public_presets');

    for (const p of publicPresets) {
      await db.run('INSERT INTO public_presets(id, name) VALUES(?, ?)', [p.id, p.name]);
      const devicePresets = p.devicePresets && typeof p.devicePresets === 'object' ? p.devicePresets : {};
      for (const [deviceId, presetIdRaw] of Object.entries(devicePresets)) {
        const presetId = Number(presetIdRaw);
        if (!deviceId) continue;
        if (!Number.isFinite(presetId) || presetId < 1) continue;
        // Skip mappings for devices that don't exist (avoids FK constraint error)
        if (!validDeviceIds.has(deviceId)) continue;
        await db.run(
          'INSERT INTO public_preset_mappings(publicPresetId, deviceId, presetId) VALUES(?, ?, ?)',
          [p.id, deviceId, presetId]
        );
      }
    }

    await db.exec('COMMIT');
  } catch (e) {
    await db.exec('ROLLBACK');
    throw e;
  }
}

export async function isEmpty(db) {
  const row = await db.get('SELECT (SELECT COUNT(*) FROM devices) AS devicesCount, (SELECT COUNT(*) FROM public_presets) AS presetsCount');
  return (row?.devicesCount ?? 0) === 0 && (row?.presetsCount ?? 0) === 0;
}

export async function getDevicePresets(db) {
  const rows = await db.all('SELECT deviceId, presetId, name FROM device_presets ORDER BY deviceId, presetId');
  const byDeviceId = {};
  
  for (const row of rows) {
    if (!byDeviceId[row.deviceId]) {
      byDeviceId[row.deviceId] = [];
    }
    byDeviceId[row.deviceId].push({
      id: row.presetId,
      name: row.name
    });
  }
  
  return byDeviceId;
}

export async function replaceDevicePresets(db, deviceId, presets) {
  await db.exec('BEGIN');
  try {
    await db.run('DELETE FROM device_presets WHERE deviceId = ?', [deviceId]);
    
    for (const preset of presets) {
      await db.run(
        'INSERT INTO device_presets(deviceId, presetId, name) VALUES(?, ?, ?)',
        [deviceId, preset.id, preset.name || '']
      );
    }
    
    await db.exec('COMMIT');
  } catch (e) {
    await db.exec('ROLLBACK');
    throw e;
  }
}
