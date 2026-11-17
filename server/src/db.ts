import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';
import type { AudioFile, Device, DevicePreset, LogEntry, LogLevel, Scene } from '../../shared/types.ts';
import type { Sequence } from '../../shared/sequence.ts';

// The schema keeps the table names of v1, so an existing data volume works unchanged.
// "public_presets" holds scenes; "device_presets" holds presets imported from WLED.
const SCHEMA = `
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
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
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
  CREATE TABLE IF NOT EXISTS sequences (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    data TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS audio_files (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    size INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS activity_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    level TEXT NOT NULL DEFAULT 'info',
    action TEXT NOT NULL,
    message TEXT NOT NULL,
    client_ip TEXT,
    user_agent TEXT,
    details TEXT
  );
`;

const MAX_LOGS = 1000;

export type Db = ReturnType<typeof openDatabase>;

function hasColumn(db: Database.Database, table: string, column: string): boolean {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all() as { name: string }[];
  return cols.some((c) => c.name === column);
}

export function openDatabase(file: string) {
  if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true });
  const db = new Database(file);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.exec(SCHEMA);

  // v2 migration: explicit ordering of scenes (v1 sorted by name).
  if (!hasColumn(db, 'public_presets', 'sort_order')) {
    db.exec('ALTER TABLE public_presets ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0');
    const rows = db.prepare('SELECT id FROM public_presets ORDER BY name COLLATE NOCASE').all() as { id: string }[];
    const upd = db.prepare('UPDATE public_presets SET sort_order = ? WHERE id = ?');
    rows.forEach((r, i) => upd.run(i, r.id));
  }
  // v2 migration: the look (colors, energy) of each imported preset, as JSON.
  if (!hasColumn(db, 'device_presets', 'look')) {
    db.exec('ALTER TABLE device_presets ADD COLUMN look TEXT');
  }
  // v2.2: effects a scene plays on layout objects, as JSON (object id -> settings).
  if (!hasColumn(db, 'public_presets', 'effects')) {
    db.exec('ALTER TABLE public_presets ADD COLUMN effects TEXT');
  }
  // v2.3: a scene can play a sequence.
  if (!hasColumn(db, 'public_presets', 'sequence_id')) {
    db.exec('ALTER TABLE public_presets ADD COLUMN sequence_id TEXT');
  }
  // v1 stored the default scene under "defaultPresetId" and minutes under "revertTimeout".
  // Same keys are used here, so no settings migration is needed.

  const stmt = {
    getSetting: db.prepare<[string], { value: string }>('SELECT value FROM settings WHERE key = ?'),
    setSetting: db.prepare(
      'INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value'
    ),
    listDevices: db.prepare('SELECT id, name, host, port, enabled FROM devices ORDER BY name COLLATE NOCASE'),
    getDevice: db.prepare('SELECT id, name, host, port, enabled FROM devices WHERE id = ?'),
    upsertDevice: db.prepare(
      `INSERT INTO devices(id, name, host, port, enabled) VALUES(@id, @name, @host, @port, @enabled)
       ON CONFLICT(id) DO UPDATE SET name=excluded.name, host=excluded.host, port=excluded.port, enabled=excluded.enabled`
    ),
    deleteDevice: db.prepare('DELETE FROM devices WHERE id = ?'),
    listScenes: db.prepare('SELECT id, name, sort_order AS sortOrder, effects, sequence_id AS sequenceId FROM public_presets ORDER BY sort_order, name COLLATE NOCASE'),
    listMappings: db.prepare('SELECT publicPresetId, deviceId, presetId FROM public_preset_mappings'),
    upsertScene: db.prepare(
      `INSERT INTO public_presets(id, name, sort_order, effects, sequence_id) VALUES(@id, @name, @sortOrder, @effects, @sequenceId)
       ON CONFLICT(id) DO UPDATE SET name=excluded.name, sort_order=excluded.sort_order, effects=excluded.effects, sequence_id=excluded.sequence_id`
    ),
    deleteScene: db.prepare('DELETE FROM public_presets WHERE id = ?'),
    deleteSceneMappings: db.prepare('DELETE FROM public_preset_mappings WHERE publicPresetId = ?'),
    insertMapping: db.prepare('INSERT INTO public_preset_mappings(publicPresetId, deviceId, presetId) VALUES(?, ?, ?)'),
    maxSort: db.prepare<[], { m: number | null }>('SELECT MAX(sort_order) AS m FROM public_presets'),
    setSort: db.prepare('UPDATE public_presets SET sort_order = ? WHERE id = ?'),
    listDevicePresets: db.prepare('SELECT deviceId, presetId, name, look FROM device_presets ORDER BY deviceId, presetId'),
    deleteDevicePresets: db.prepare('DELETE FROM device_presets WHERE deviceId = ?'),
    insertDevicePreset: db.prepare('INSERT INTO device_presets(deviceId, presetId, name, look) VALUES(?, ?, ?, ?)'),
    countUsers: db.prepare<[], { c: number }>('SELECT COUNT(*) AS c FROM admin_users'),
    userByName: db.prepare<[string], { id: string; username: string; passwordHash: string }>(
      'SELECT id, username, password_hash AS passwordHash FROM admin_users WHERE username = ?'
    ),
    userById: db.prepare<[string], { id: string; username: string }>('SELECT id, username FROM admin_users WHERE id = ?'),
    insertUser: db.prepare('INSERT INTO admin_users(id, username, password_hash) VALUES(?, ?, ?) ON CONFLICT(username) DO NOTHING'),
    updatePassword: db.prepare("UPDATE admin_users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?"),
    insertSession: db.prepare('INSERT INTO sessions(token_hash, user_id, expires_at) VALUES(?, ?, ?)'),
    getSession: db.prepare<[string], { userId: string; expiresAt: number }>(
      'SELECT user_id AS userId, expires_at AS expiresAt FROM sessions WHERE token_hash = ?'
    ),
    touchSession: db.prepare('UPDATE sessions SET expires_at = ? WHERE token_hash = ?'),
    deleteSession: db.prepare('DELETE FROM sessions WHERE token_hash = ?'),
    purgeSessions: db.prepare('DELETE FROM sessions WHERE expires_at < ?'),
    insertLog: db.prepare(
      'INSERT INTO activity_logs(level, action, message, client_ip, user_agent, details) VALUES(?, ?, ?, ?, ?, ?)'
    ),
    pruneLogs: db.prepare(`DELETE FROM activity_logs WHERE id <= (SELECT id FROM activity_logs ORDER BY id DESC LIMIT 1 OFFSET ${MAX_LOGS})`),
    listLogs: db.prepare(
      `SELECT id, timestamp, level, action, message, client_ip AS clientIp, user_agent AS userAgent, details
       FROM activity_logs WHERE (@action IS NULL OR action = @action OR (@action = 'error' AND level = 'error'))
       ORDER BY id DESC LIMIT @limit`
    ),
    listSequences: db.prepare<[], { id: string; data: string; updatedAt: string }>('SELECT id, data, updated_at AS updatedAt FROM sequences ORDER BY name COLLATE NOCASE'),
    getSequence: db.prepare<[string], { id: string; data: string; updatedAt: string }>('SELECT id, data, updated_at AS updatedAt FROM sequences WHERE id = ?'),
    upsertSequence: db.prepare(
      `INSERT INTO sequences(id, name, data, updated_at) VALUES(@id, @name, @data, @updatedAt)
       ON CONFLICT(id) DO UPDATE SET name=excluded.name, data=excluded.data, updated_at=excluded.updated_at`
    ),
    deleteSequence: db.prepare('DELETE FROM sequences WHERE id = ?'),
    clearSceneSequence: db.prepare('UPDATE public_presets SET sequence_id = NULL WHERE sequence_id = ?'),
    listAudio: db.prepare('SELECT id, name, type, size, created_at AS createdAt FROM audio_files ORDER BY created_at DESC'),
    getAudio: db.prepare<[string], AudioFile>('SELECT id, name, type, size, created_at AS createdAt FROM audio_files WHERE id = ?'),
    insertAudio: db.prepare('INSERT INTO audio_files(id, name, type, size) VALUES(?, ?, ?, ?)'),
    deleteAudio: db.prepare('DELETE FROM audio_files WHERE id = ?'),
    isEmpty: db.prepare<[], { n: number }>('SELECT (SELECT COUNT(*) FROM devices) + (SELECT COUNT(*) FROM public_presets) AS n')
  };

  const rowToDevice = (r: any): Device => ({ id: r.id, name: r.name, host: r.host, port: r.port, enabled: Boolean(r.enabled) });

  function listScenes(): Scene[] {
    const rows = stmt.listScenes.all() as (Omit<Scene, 'devicePresets' | 'effects' | 'sequenceId'> & { effects: string | null; sequenceId: string | null })[];
    const scenes: Scene[] = rows.map(({ effects, sequenceId, ...s }) => {
      const fx = effects ? (safeJson(effects) as Scene['effects']) : null;
      return { ...s, devicePresets: {}, ...(fx && typeof fx === 'object' && Object.keys(fx).length ? { effects: fx } : {}), ...(sequenceId ? { sequenceId } : {}) };
    });
    const byId = new Map(scenes.map((s) => [s.id, s]));
    for (const m of stmt.listMappings.all() as { publicPresetId: string; deviceId: string; presetId: number }[]) {
      const scene = byId.get(m.publicPresetId);
      if (scene) scene.devicePresets[m.deviceId] = Number(m.presetId);
    }
    return scenes;
  }

  const saveSceneTx = db.transaction((scene: Scene) => {
    const effects = scene.effects && Object.keys(scene.effects).length ? JSON.stringify(scene.effects) : null;
    stmt.upsertScene.run({ id: scene.id, name: scene.name, sortOrder: scene.sortOrder, effects, sequenceId: scene.sequenceId ?? null });
    stmt.deleteSceneMappings.run(scene.id);
    const deviceIds = new Set((stmt.listDevices.all() as { id: string }[]).map((d) => d.id));
    for (const [deviceId, presetId] of Object.entries(scene.devicePresets)) {
      if (deviceIds.has(deviceId) && Number.isInteger(presetId) && presetId >= 1) {
        stmt.insertMapping.run(scene.id, deviceId, presetId);
      }
    }
  });

  return {
    raw: db,
    close: () => db.close(),
    isEmpty: () => (stmt.isEmpty.get()?.n ?? 0) === 0,

    getSetting(key: string): string | null {
      return stmt.getSetting.get(key)?.value ?? null;
    },
    setSetting(key: string, value: string | number | boolean | null) {
      stmt.setSetting.run(key, value == null ? '' : String(value));
    },

    listDevices: (): Device[] => stmt.listDevices.all().map(rowToDevice),
    getDevice: (id: string): Device | null => {
      const r = stmt.getDevice.get(id);
      return r ? rowToDevice(r) : null;
    },
    saveDevice(d: Device) {
      stmt.upsertDevice.run({ ...d, enabled: d.enabled ? 1 : 0 });
    },
    deleteDevice: (id: string) => stmt.deleteDevice.run(id).changes > 0,

    listScenes,
    getScene: (id: string) => listScenes().find((s) => s.id === id) ?? null,
    nextSortOrder: () => (stmt.maxSort.get()?.m ?? -1) + 1,
    saveScene: (scene: Scene) => saveSceneTx(scene),
    deleteScene: (id: string) => stmt.deleteScene.run(id).changes > 0,
    reorderScenes: db.transaction((ids: string[]) => {
      ids.forEach((id, i) => stmt.setSort.run(i, id));
    }),
    replaceScenes: db.transaction((scenes: Scene[]) => {
      db.exec('DELETE FROM public_preset_mappings; DELETE FROM public_presets;');
      for (const s of scenes) saveSceneTx(s);
    }),

    listSequences(): Sequence[] {
      return stmt.listSequences.all().flatMap((r) => {
        const seq = safeJson(r.data) as Sequence | null;
        return seq && typeof seq === 'object' ? [{ ...seq, id: r.id, updatedAt: r.updatedAt }] : [];
      });
    },
    getSequence(id: string): Sequence | null {
      const r = stmt.getSequence.get(id);
      const seq = r ? (safeJson(r.data) as Sequence | null) : null;
      return r && seq && typeof seq === 'object' ? { ...seq, id: r.id, updatedAt: r.updatedAt } : null;
    },
    saveSequence(seq: Sequence): Sequence {
      const updatedAt = new Date().toISOString();
      const { updatedAt: _u, ...data } = seq;
      stmt.upsertSequence.run({ id: seq.id, name: seq.name, data: JSON.stringify(data), updatedAt });
      return { ...seq, updatedAt };
    },
    /** Deletes a sequence; scenes that played it play nothing from it any more. */
    deleteSequence: db.transaction((id: string) => {
      stmt.clearSceneSequence.run(id);
      return stmt.deleteSequence.run(id).changes > 0;
    }),

    listAudio: (): AudioFile[] => stmt.listAudio.all() as AudioFile[],
    getAudio: (id: string): AudioFile | null => stmt.getAudio.get(id) ?? null,
    addAudio: (f: Omit<AudioFile, 'createdAt'>) => stmt.insertAudio.run(f.id, f.name, f.type, f.size),
    deleteAudio: (id: string) => stmt.deleteAudio.run(id).changes > 0,

    listDevicePresets(): Record<string, DevicePreset[]> {
      const out: Record<string, DevicePreset[]> = {};
      for (const r of stmt.listDevicePresets.all() as { deviceId: string; presetId: number; name: string; look: string | null }[]) {
        const look = r.look ? (safeJson(r.look) as { colors?: string[]; energy?: number }) : null;
        (out[r.deviceId] ??= []).push({ id: r.presetId, name: r.name, colors: look?.colors ?? [], energy: look?.energy });
      }
      return out;
    },
    replaceDevicePresets: db.transaction((deviceId: string, presets: DevicePreset[]) => {
      stmt.deleteDevicePresets.run(deviceId);
      for (const p of presets) stmt.insertDevicePreset.run(deviceId, p.id, p.name, JSON.stringify({ colors: p.colors ?? [], energy: p.energy ?? null }));
    }),

    countUsers: () => stmt.countUsers.get()?.c ?? 0,
    getUserByName: (username: string) => stmt.userByName.get(username) ?? null,
    getUserById: (id: string) => stmt.userById.get(id) ?? null,
    createUser: (id: string, username: string, passwordHash: string) => stmt.insertUser.run(id, username, passwordHash).changes > 0,

    updatePassword: (id: string, passwordHash: string) => stmt.updatePassword.run(passwordHash, id),
    createSession: (tokenHash: string, userId: string, expiresAt: number) => stmt.insertSession.run(tokenHash, userId, expiresAt),
    getSession: (tokenHash: string) => stmt.getSession.get(tokenHash) ?? null,
    touchSession: (tokenHash: string, expiresAt: number) => stmt.touchSession.run(expiresAt, tokenHash),
    deleteSession: (tokenHash: string) => stmt.deleteSession.run(tokenHash),
    purgeSessions: () => stmt.purgeSessions.run(Date.now()),

    addLog(entry: { level: LogLevel; action: string; message: string; clientIp?: string | null; userAgent?: string | null; details?: unknown }) {
      stmt.insertLog.run(
        entry.level,
        entry.action,
        entry.message,
        entry.clientIp ?? null,
        entry.userAgent ?? null,
        entry.details == null ? null : JSON.stringify(entry.details)
      );
      stmt.pruneLogs.run();
    },
    listLogs(limit: number, action: string | null): LogEntry[] {
      return (stmt.listLogs.all({ limit, action }) as any[]).map((r) => ({
        ...r,
        // SQLite datetime('now') is UTC without a zone marker.
        timestamp: r.timestamp.includes('T') ? r.timestamp : `${r.timestamp.replace(' ', 'T')}Z`,
        details: r.details ? safeJson(r.details) : null
      }));
    }
  };
}

function safeJson(s: string): unknown {
  try {
    return JSON.parse(s);
  } catch {
    return s;
  }
}
