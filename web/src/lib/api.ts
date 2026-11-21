import type { PreviewRequest, SequencePreviewRequest } from '../../../shared/editorView.ts';
import type { GameArea, Layout, OutputInfo } from '../../../shared/layout.ts';
import type { Sequence, SequenceSummary } from '../../../shared/sequence.ts';
import type { LineAdmin, LineSettings } from '../../../shared/line.ts';
import type {
  AudioFile,
  ApplyResult,
  DevicePreset,
  DeviceWithStatus,
  DiscoveredDevice,
  LightControls,
  LogEntry,
  PublicState,
  Scene,
  Passkey,
  SessionInfo,
  Settings
} from '../../../shared/types.ts';
import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON
} from '@simplewebauthn/browser';

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, init: { method?: string; body?: unknown } = {}): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, {
      method: init.method ?? (init.body !== undefined ? 'POST' : 'GET'),
      headers: init.body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
      body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
      credentials: 'same-origin'
    });
  } catch {
    throw new ApiError(0, 'Cannot reach the server. Check that it is running, then try again.');
  }
  if (res.status === 502 || res.status === 504) {
    // The Vite dev proxy answers 502/504 when the API process is down.
    const type = res.headers.get('content-type') ?? '';
    if (!type.includes('application/json')) throw new ApiError(res.status, 'Cannot reach the server. Check that it is running, then try again.');
  }
  const text = await res.text();
  let json: any = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    /* not JSON */
  }
  if (!res.ok) throw new ApiError(res.status, json?.error ?? `Request failed (${res.status})`);
  return json as T;
}

/** A scene or color that waits in line (the lights are busy). */
export interface Queued {
  queued: { place: number; message: string };
}

export const isQueued = (r: unknown): r is Queued => !!r && typeof r === 'object' && 'queued' in r;

export interface Overview {
  devices: DeviceWithStatus[];
  scenes: Scene[];
  devicePresets: Record<string, DevicePreset[]>;
  settings: Settings;
  state: PublicState;
  controls: LightControls;
}

export type PresetImport = { deviceId: string; ok: true; count: number } | { deviceId: string; ok: false; error: string };

export interface DeviceInput {
  name: string;
  host: string;
  port: number;
  enabled: boolean;
}

/** A layout file, as Layout → File → Export writes it. */
export interface LayoutFile {
  kind: 'wled-layout';
  version: number;
  exportedAt: string;
  layout: Layout;
  devices: { id: string; name: string; host: string; port: number }[];
  gameArea: GameArea | null;
  pictures: { background: { type: string; data: string } | null; aerial: { type: string; data: string } | null };
}

export const api = {
  layout: () => request<Layout>('/api/layout'),
  saveLayout: (layout: Layout) => request<Layout>('/api/admin/layout', { method: 'PUT', body: layout }),
  previewLayout: (req: PreviewRequest) => request<{ devices: string[] }>('/api/admin/layout/preview', { method: 'POST', body: { active: true, ...req } }),
  // keepalive: the request still goes out when the page is closing.
  stopLayoutPreview: () => fetch('/api/admin/layout/preview', { method: 'DELETE', credentials: 'same-origin', keepalive: true }),
  gameArea: () => request<{ area: GameArea | null }>('/api/admin/games/area'),
  saveGameArea: (area: GameArea) => request<{ area: GameArea | null }>('/api/admin/games/area', { method: 'PUT', body: area }),
  playOutput: () => request<OutputInfo | null>('/api/admin/play/output'),
  removeScore: (id: number) => request<{ ok: true }>(`/api/admin/play/scores/${id}`, { method: 'DELETE' }),
  setPlayOutput: (body: { enabled?: boolean; brightness?: number }) => request<OutputInfo>('/api/admin/play/output', { method: 'PUT', body }),
  /** The layout file (layout, devices, game area and pictures) for the saved layout. */
  exportLayout: () => request<LayoutFile>('/api/admin/layout/export'),
  /** Replaces the layout (and its pictures) with a layout file, or a bare layout. */
  importLayout: (file: unknown) => request<{ layout: Layout; unmatched: number }>('/api/admin/layout/import', { body: file }),
  removeBackground: () => request<Layout>('/api/admin/layout/background', { method: 'DELETE' }),
  async uploadBackground(file: File): Promise<Layout> {
    const res = await fetch('/api/admin/layout/background', { method: 'POST', headers: { 'Content-Type': file.type }, body: file, credentials: 'same-origin' });
    const json = await res.json().catch(() => null);
    if (!res.ok) throw new ApiError(res.status, json?.error ?? `Upload failed (${res.status})`);
    return json as Layout;
  },
  removeAerial: () => request<Layout>('/api/admin/layout/aerial', { method: 'DELETE' }),
  async uploadAerial(file: File): Promise<{ url: string }> {
    const res = await fetch('/api/admin/layout/aerial', { method: 'POST', headers: { 'Content-Type': file.type }, body: file, credentials: 'same-origin' });
    const json = await res.json().catch(() => null);
    if (!res.ok) throw new ApiError(res.status, json?.error ?? `Upload failed (${res.status})`);
    return json as { url: string };
  },

  state: () => request<PublicState>('/api/state'),
  applyScene: (id: string) => request<ApplyResult | Queued>(`/api/scenes/${encodeURIComponent(id)}/apply`, { method: 'POST' }),
  applyColor: (color: string) => request<ApplyResult | Queued>('/api/color', { body: { color } }),
  leaveLine: () => request<{ ok: true }>('/api/line/leave', { method: 'POST' }),
  line: () => request<LineAdmin>('/api/admin/line'),
  saveLine: (s: LineSettings) => request<LineAdmin>('/api/admin/line', { method: 'PUT', body: s }),
  removeFromLine: (id: number) => request<LineAdmin>(`/api/admin/line/${id}`, { method: 'DELETE' }),
  passTurn: () => request<LineAdmin>('/api/admin/line/pass', { method: 'POST' }),

  session: () => request<SessionInfo>('/api/auth/session'),
  login: (username: string, password: string) => request<{ user: SessionInfo['user'] }>('/api/auth/login', { body: { username, password } }),
  bootstrap: (username: string, password: string) => request<{ user: SessionInfo['user'] }>('/api/auth/bootstrap', { body: { username, password } }),
  logout: () => request('/api/auth/logout', { method: 'POST' }),
  changePassword: (current: string, next: string) => request('/api/admin/auth/password', { body: { current, next } }),

  /** Passkeys (see lib/passkeys.ts): a challenge to sign, then the signed answer. */
  passkeyOptions: () => request<{ options: PublicKeyCredentialRequestOptionsJSON }>('/api/auth/passkey/options', { body: {} }),
  passkeyLogin: (response: AuthenticationResponseJSON) => request<{ user: SessionInfo['user'] }>('/api/auth/passkey/login', { body: { response } }),
  passkeys: () => request<Passkey[]>('/api/admin/passkeys'),
  passkeyRegistration: (password: string) => request<{ options: PublicKeyCredentialCreationOptionsJSON }>('/api/admin/passkeys/options', { body: { password } }),
  addPasskey: (name: string, response: RegistrationResponseJSON) => request<Passkey>('/api/admin/passkeys', { body: { name, response } }),
  renamePasskey: (id: string, name: string) => request<Passkey[]>(`/api/admin/passkeys/${encodeURIComponent(id)}`, { method: 'PATCH', body: { name } }),
  removePasskey: (id: string) => request<Passkey[]>(`/api/admin/passkeys/${encodeURIComponent(id)}`, { method: 'DELETE' }),

  overview: () => request<Overview>('/api/admin/overview'),

  /** Power and brightness: for every light, or one device (deviceId). */
  lightControls: () => request<LightControls>('/api/admin/lights'),
  setPower: (on: boolean, deviceId: string | null = null) =>
    request<{ controls: LightControls; result: ApplyResult }>('/api/admin/lights/power', { method: 'PUT', body: { on, deviceId } }),
  /** level: percent (1 to 100); null hands it back (to the scenes, or for a device to "all lights"). */
  setBrightness: (level: number | null, deviceId: string | null = null) =>
    request<{ controls: LightControls; result: ApplyResult }>('/api/admin/lights/brightness', { method: 'PUT', body: { level, deviceId } }),

  addDevice: (d: DeviceInput) => request<DeviceWithStatus & { presets: PresetImport | null }>('/api/admin/devices', { body: d }),
  addDevices: (devices: DeviceInput[]) => request<{ added: unknown[]; presets: PresetImport[] }>('/api/admin/devices/bulk', { body: { devices } }),
  updateDevice: (id: string, d: DeviceInput) => request(`/api/admin/devices/${id}`, { method: 'PUT', body: d }),
  deleteDevice: (id: string) => request(`/api/admin/devices/${id}`, { method: 'DELETE' }),
  probe: (host: string, port: number) =>
    request<{ ok: true; info: { name?: string; ver?: string } } | { ok: false; error: string }>('/api/admin/probe', { body: { host, port } }),
  syncPresets: (id: string) => request<{ count: number }>(`/api/admin/devices/${id}/presets/sync`, { method: 'POST' }),
  syncAllPresets: () =>
    request<{ results: ({ deviceId: string; ok: true; count: number } | { deviceId: string; ok: false; error: string })[] }>(
      '/api/admin/devices/presets/sync',
      { method: 'POST' }
    ),
  applyDevicePreset: (id: string, presetId: number) => request(`/api/admin/devices/${id}/apply`, { body: { presetId } }),
  discover: (subnets?: string[]) => request<{ found: DiscoveredDevice[]; subnets: string[] }>('/api/admin/discover', { body: { subnets } }),

  createScene: (s: Pick<Scene, 'name' | 'devicePresets' | 'effects' | 'sequenceId'>) => request<Scene>('/api/admin/scenes', { body: s }),
  /** Leave `effects` (or `sequenceId`) out to keep the scene's. */
  updateScene: (id: string, s: Pick<Scene, 'name' | 'devicePresets' | 'effects' | 'sequenceId'>) => request<Scene>(`/api/admin/scenes/${id}`, { method: 'PUT', body: s }),

  sequences: () => request<{ sequences: SequenceSummary[] }>('/api/admin/sequences'),
  sequence: (id: string) => request<Sequence>(`/api/admin/sequences/${encodeURIComponent(id)}`),
  createSequence: (s: Omit<Sequence, 'id' | 'updatedAt'>) => request<Sequence>('/api/admin/sequences', { body: s }),
  saveSequence: ({ id, updatedAt: _u, ...s }: Sequence) => request<Sequence>(`/api/admin/sequences/${encodeURIComponent(id)}`, { method: 'PUT', body: s }),
  deleteSequence: (id: string) => request(`/api/admin/sequences/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  // inFront: sent only by an editor window in front (see useInFront).
  previewSequence: (req: SequencePreviewRequest) => request<{ devices: string[] }>('/api/admin/sequence-preview', { method: 'POST', body: { active: true, inFront: true, ...req } }),
  stopSequencePreview: () => fetch('/api/admin/sequence-preview', { method: 'DELETE', credentials: 'same-origin', keepalive: true }),
  audioFiles: () => request<{ files: AudioFile[] }>('/api/admin/audio'),
  audioUrl: (id: string) => `/api/admin/audio/${encodeURIComponent(id)}`,
  async uploadAudio(file: File): Promise<AudioFile> {
    const type = file.type && file.type.startsWith('audio/') ? file.type : guessAudioType(file.name);
    const res = await fetch('/api/admin/audio', { method: 'POST', headers: { 'Content-Type': type, 'X-File-Name': encodeURIComponent(file.name) }, body: file, credentials: 'same-origin' });
    const json = await res.json().catch(() => null);
    if (!res.ok) throw new ApiError(res.status, json?.error ?? `Upload failed (${res.status})`);
    return json as AudioFile;
  },
  deleteScene: (id: string) => request(`/api/admin/scenes/${id}`, { method: 'DELETE' }),
  reorderScenes: (ids: string[]) => request('/api/admin/scenes/order', { method: 'PUT', body: { ids } }),
  exportScenes: () => request<unknown>('/api/admin/scenes/export'),
  importScenes: (file: unknown) => request<{ restored: number }>('/api/admin/scenes/import', { body: file }),

  saveSettings: (s: Settings) => request<Settings>('/api/admin/settings', { method: 'PUT', body: s }),
  cancelRevert: () => request('/api/admin/revert/cancel', { method: 'POST' }),

  logs: (action: string | null, limit = 300) =>
    request<{ logs: LogEntry[] }>(`/api/admin/logs?limit=${limit}${action ? `&action=${encodeURIComponent(action)}` : ''}`)
};

function guessAudioType(name: string): string {
  const ext = name.split('.').pop()?.toLowerCase();
  return ext === 'wav' ? 'audio/wav' : ext === 'ogg' || ext === 'oga' ? 'audio/ogg' : ext === 'm4a' || ext === 'aac' ? 'audio/mp4' : ext === 'flac' ? 'audio/flac' : 'audio/mpeg';
}
