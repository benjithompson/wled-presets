const els = {
  tabs: Array.from(document.querySelectorAll('.tab')),
  panels: {
    public: document.getElementById('public'),
    admin: document.getElementById('admin')
  },

  presetSelect: document.getElementById('presetSelect'),
  applyBtn: document.getElementById('applyBtn'),
  refreshBtn: document.getElementById('refreshBtn'),
  publicStatus: document.getElementById('publicStatus'),

  // Profile menu
  profileBtn: document.getElementById('profileBtn'),
  profileDropdown: document.getElementById('profileDropdown'),
  adminLogoutBtn: document.getElementById('adminLogoutBtn'),

  // Admin tabs
  adminTabs: Array.from(document.querySelectorAll('.admin-tab')),
  presetsTab: document.getElementById('presetsTab'),
  devicesTab: document.getElementById('devicesTab'),
  logsTab: document.getElementById('logsTab'),

  discoverBtn: document.getElementById('discoverBtn'),
  addDeviceBtn: document.getElementById('addDeviceBtn'),
  devicesList: document.getElementById('devicesList'),
  devicesStatus: document.getElementById('devicesStatus'),

  devicePresetsSelect: document.getElementById('devicePresetsSelect'),
  devicePresetsList: document.getElementById('devicePresetsList'),
  devicePresetsStatus: document.getElementById('devicePresetsStatus'),

  importPresetsBtn: document.getElementById('importPresetsBtn'),
  addPresetBtn: document.getElementById('addPresetBtn'),
  backupPresetsBtn: document.getElementById('backupPresetsBtn'),
  restorePresetsBtn: document.getElementById('restorePresetsBtn'),
  restoreFileInput: document.getElementById('restoreFileInput'),
  presetEditor: document.getElementById('presetEditor'),
  presetsList: document.getElementById('presetsList'),
  presetsStatus: document.getElementById('presetsStatus'),

  defaultPresetSelect: document.getElementById('defaultPresetSelect'),
  revertTimeoutInput: document.getElementById('revertTimeoutInput'),
  saveSettingsBtn: document.getElementById('saveSettingsBtn'),
  settingsStatus: document.getElementById('settingsStatus'),

  // Logs
  logsList: document.getElementById('logsList'),
  logsStatus: document.getElementById('logsStatus'),
  logsFilter: document.getElementById('logsFilter'),
  refreshLogsBtn: document.getElementById('refreshLogsBtn')
};

const hasPublicUi = Boolean(els.presetSelect && els.applyBtn && els.refreshBtn && els.publicStatus);
const hasAdminUi = Boolean(
  els.adminLogoutBtn &&
  els.devicesList &&
  els.devicesStatus &&
  els.devicePresetsSelect &&
  els.devicePresetsList &&
  els.devicePresetsStatus &&
  els.presetsList &&
  els.presetsStatus &&
  els.addDeviceBtn &&
  els.discoverBtn &&
  els.addPresetBtn &&
  els.importPresetsBtn &&
  els.presetEditor &&
  els.defaultPresetSelect &&
  els.revertTimeoutInput &&
  els.saveSettingsBtn &&
  els.logsList
);

const state = {
  publicConfig: { devices: [], publicPresets: [] },
  admin: {
    unlocked: false,
    config: { devices: [], publicPresets: [] },
    importedPresetsByDeviceId: {},
    editingPresetId: null
  }
};

function setStatus(el, msg) {
  if (el) el.textContent = msg || '';
}

function escapeHtml(s) {
  return String(s)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function setActiveTab(tabName) {
  if (!els.tabs.length) return;
  for (const tab of els.tabs) tab.classList.toggle('is-active', tab.dataset.tab === tabName);
  for (const [name, panel] of Object.entries(els.panels)) {
    if (!panel) continue;
    panel.classList.toggle('is-active', name === tabName);
  }
}

async function api(path, { method = 'GET', body } = {}) {
  const headers = {};
  if (body) headers['Content-Type'] = 'application/json';

  const res = await fetch(path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined
  });

  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { json = null; }

  if (!res.ok) {
    const msg = (json && json.error) ? json.error : `Request failed (${res.status})`;
    const err = new Error(msg);
    err.status = res.status;
    throw err;
  }

  return json;
}

async function authMe() {
  try {
    await api('/api/auth/me');
    state.admin.unlocked = true;
    return true;
  } catch {
    // If not authenticated, server will redirect to /login via middleware
    window.location.href = '/login?redirect=' + encodeURIComponent(window.location.pathname);
    return false;
  }
}

function renderPublicSelects() {
  const { publicPresets } = state.publicConfig;

  els.presetSelect.innerHTML = publicPresets.length
    ? publicPresets.map((p) => `<option value="${p.id}">${escapeHtml(p.name)}</option>`).join('')
    : `<option value="">No presets available</option>`;

  els.applyBtn.disabled = !publicPresets.length;
}

async function loadPublic() {
  setStatus(els.publicStatus, 'Loading…');
  try {
    state.publicConfig = await api('/api/config/public');
    renderPublicSelects();
    setStatus(els.publicStatus, '');
  } catch (e) {
    setStatus(els.publicStatus, e.message);
  }
}

async function applyPreset() {
  const publicPresetId = els.presetSelect.value;
  if (!publicPresetId) return;

  els.applyBtn.disabled = true;
  setStatus(els.publicStatus, 'Applying…');
  try {
    const out = await api('/api/apply', { method: 'POST', body: { publicPresetId } });
    const applied = Array.isArray(out.applied) ? out.applied.length : 0;
    const skipped = Array.isArray(out.skipped) ? out.skipped.length : 0;
    setStatus(els.publicStatus, `Done. Applied to ${applied} device(s)${skipped ? ` (${skipped} skipped)` : ''}.`);
  } catch (e) {
    setStatus(els.publicStatus, e.message);
  } finally {
    els.applyBtn.disabled = false;
  }
}

function renderDevices() {
  const devices = state.admin.config.devices || [];
  els.devicesList.innerHTML = devices.length
    ? devices.map((d) => {
        const enabled = !!d.enabled;
        return `
          <div class="item">
            <div class="meta">
              <div class="title">${escapeHtml(d.name || d.host)}</div>
              <div class="subtitle">${escapeHtml(d.host)}:${escapeHtml(d.port ?? 80)} · ${enabled ? 'Enabled' : 'Disabled'}</div>
            </div>
            <div class="controls">
              <span class="pill">${enabled ? 'Public' : 'Hidden'}</span>
              <button class="ghost" data-action="toggle" data-id="${escapeHtml(d.id)}" type="button">${enabled ? 'Disable' : 'Enable'}</button>
              <button class="ghost" data-action="edit" data-id="${escapeHtml(d.id)}" type="button">Edit</button>
              <button class="ghost" data-action="delete" data-id="${escapeHtml(d.id)}" type="button">Remove</button>
            </div>
          </div>
        `;
      }).join('')
    : `<div class="muted">No devices yet.</div>`;
}

function renderPresets() {
  const presets = state.admin.config.publicPresets || [];
  const defaultPresetId = state.admin.config.defaultPresetId || '';
  const currentPresetId = state.admin.config.currentPresetId || '';

  function mappedCount(p) {
    const m = p && typeof p.devicePresets === 'object' && p.devicePresets ? p.devicePresets : {};
    return Object.values(m).filter((v) => Number.isFinite(Number(v)) && Number(v) >= 1).length;
  }

  els.presetsList.innerHTML = presets.length
    ? presets.map((p) => {
        const isDefault = p.id === defaultPresetId;
        const isCurrent = p.id === currentPresetId;
        const defaultBtnClass = isDefault ? 'default-btn is-default' : 'default-btn ghost';
        const defaultBtnText = isDefault ? 'Default' : 'Set default';
        const itemClass = isCurrent ? 'item is-active' : 'item';
        return `
        <div class="${itemClass}">
          <div class="meta">
            <div class="title">${escapeHtml(p.name || 'Untitled')}</div>
            <div class="subtitle">Mapped devices: ${escapeHtml(mappedCount(p))}</div>
          </div>
          <div class="controls">
            <button class="${defaultBtnClass}" data-action="setDefault" data-id="${escapeHtml(p.id)}" type="button"${isDefault ? ' disabled' : ''}>${defaultBtnText}</button>
            <button class="primary" data-action="applyPreset" data-id="${escapeHtml(p.id)}" type="button">Apply</button>
            <button class="ghost" data-action="editPreset" data-id="${escapeHtml(p.id)}" type="button">Edit</button>
            <button class="ghost" data-action="deletePreset" data-id="${escapeHtml(p.id)}" type="button">Remove</button>
          </div>
        </div>
      `;
      }).join('')
    : `<div class="muted">No public presets yet.</div>`;
}

function renderDevicePresetsDropdown() {
  const devices = state.admin.config.devices || [];
  
  els.devicePresetsSelect.innerHTML = '<option value="">Select a device</option>' +
    devices
      .filter(d => d.enabled)
      .map(d => `<option value="${escapeHtml(d.id)}">${escapeHtml(d.name || d.host)}</option>`)
      .join('');
}

function renderDevicePresets() {
  const selectedDeviceId = els.devicePresetsSelect.value;
  
  if (!selectedDeviceId) {
    els.devicePresetsList.innerHTML = '<div class="muted">Select a device to view its presets.</div>';
    setStatus(els.devicePresetsStatus, '');
    return;
  }
  
  const presets = state.admin.importedPresetsByDeviceId[selectedDeviceId];
  
  if (!presets || !Array.isArray(presets) || presets.length === 0) {
    els.devicePresetsList.innerHTML = '<div class="muted">No presets imported for this device. Use "Import presets" button.</div>';
    setStatus(els.devicePresetsStatus, '');
    return;
  }
  
  els.devicePresetsList.innerHTML = presets.map(p => `
    <div class="item">
      <div class="meta">
        <div class="title">${escapeHtml(p.name || 'Untitled')}</div>
        <div class="subtitle">ID: ${escapeHtml(p.id)}</div>
      </div>
    </div>
  `).join('');
  
  setStatus(els.devicePresetsStatus, `${presets.length} preset(s) imported`);
}

async function loadAdminConfig() {
  setStatus(els.devicesStatus, 'Loading…');
  setStatus(els.presetsStatus, 'Loading…');
  try {
    state.admin.config = await api('/api/admin/config');
    
    // Load device presets from config if available
    if (state.admin.config.devicePresets) {
      state.admin.importedPresetsByDeviceId = state.admin.config.devicePresets;
    }
    
    renderDevices();
    renderDevicePresetsDropdown();
    renderDevicePresets();
    renderPresets();
    renderSettings();
    setStatus(els.devicesStatus, '');
    setStatus(els.presetsStatus, '');
  } catch (e) {
    setStatus(els.devicesStatus, e.message);
    setStatus(els.presetsStatus, e.message);
  }
}

function renderSettings() {
  const presets = state.admin.config.publicPresets || [];
  const defaultPresetId = state.admin.config.defaultPresetId || '';
  const revertTimeout = state.admin.config.revertTimeout ?? 0;

  // Populate default preset dropdown
  els.defaultPresetSelect.innerHTML = '<option value="">(None)</option>' +
    presets.map(p => `<option value="${escapeHtml(p.id)}" ${p.id === defaultPresetId ? 'selected' : ''}>${escapeHtml(p.name || 'Untitled')}</option>`).join('');

  // Set revert timeout input
  els.revertTimeoutInput.value = revertTimeout > 0 ? revertTimeout : '';
}

async function saveSettings() {
  const defaultPresetId = els.defaultPresetSelect.value || null;
  const revertTimeout = Math.max(0, parseInt(els.revertTimeoutInput.value, 10) || 0);

  setStatus(els.settingsStatus, 'Saving…');
  try {
    await api('/api/admin/settings', {
      method: 'POST',
      body: { defaultPresetId, revertTimeout }
    });
    state.admin.config.defaultPresetId = defaultPresetId;
    state.admin.config.revertTimeout = revertTimeout;
    setStatus(els.settingsStatus, 'Saved.');
    setTimeout(() => setStatus(els.settingsStatus, ''), 2000);
  } catch (e) {
    setStatus(els.settingsStatus, e.message);
  }
}

// Logs
let allLogs = [];
let logsEventSource = null;

async function loadLogs() {
  if (!els.logsList) return;
  setStatus(els.logsStatus, 'Loading…');
  try {
    const data = await api('/api/admin/logs?limit=100');
    allLogs = data.logs || [];
    renderLogs();
    setStatus(els.logsStatus, '');
  } catch (e) {
    setStatus(els.logsStatus, e.message);
  }
}

function renderLogs() {
  if (!els.logsList) return;
  
  const filter = els.logsFilter?.value || '';
  let logs = allLogs;
  
  if (filter === 'error') {
    logs = allLogs.filter(log => log.level === 'error' || log.level === 'warn');
  } else if (filter) {
    logs = allLogs.filter(log => log.action === filter);
  }
  
  if (!logs.length) {
    els.logsList.innerHTML = filter 
      ? '<div class="logs-empty">No logs matching filter.</div>'
      : '<div class="logs-empty">No activity logged yet.</div>';
    return;
  }

  els.logsList.innerHTML = logs.map(log => {
    const time = new Date(log.timestamp + 'Z').toLocaleString();
    const details = log.clientIp && log.clientIp !== 'system' && log.clientIp !== 'server'
      ? `<div class="log-details">IP: ${escapeHtml(log.clientIp)} · ${escapeHtml(log.userAgent || 'Unknown client')}</div>`
      : '';
    const levelClass = log.level === 'error' || log.level === 'warn' ? ' log-error' : '';
    return `
      <div class="log-entry${levelClass}">
        <span class="log-time">${escapeHtml(time)}</span>
        <span class="log-action ${escapeHtml(log.action)}">${escapeHtml(log.action.replace(/_/g, ' '))}</span>
        <span class="log-message">${escapeHtml(log.message)}</span>
        ${details}
      </div>
    `;
  }).join('');
}

function connectLogsStream() {
  if (logsEventSource) {
    logsEventSource.close();
  }
  
  logsEventSource = new EventSource('/api/admin/logs/stream');
  
  logsEventSource.onmessage = (event) => {
    if (event.data === 'update') {
      loadLogs();
    }
  };
  
  logsEventSource.onerror = () => {
    // Reconnect after 5 seconds on error
    logsEventSource.close();
    logsEventSource = null;
    setTimeout(connectLogsStream, 5000);
  };
}

function disconnectLogsStream() {
  if (logsEventSource) {
    logsEventSource.close();
    logsEventSource = null;
  }
}

// Admin tab switching
function setAdminTab(tabName) {
  for (const tab of els.adminTabs) {
    tab.classList.toggle('is-active', tab.dataset.tab === tabName);
  }
  
  const tabPanels = { presets: els.presetsTab, devices: els.devicesTab, logs: els.logsTab };
  for (const [name, panel] of Object.entries(tabPanels)) {
    if (panel) panel.classList.toggle('is-active', name === tabName);
  }
  
  // Connect/disconnect SSE stream and load logs when switching tabs
  if (tabName === 'logs') {
    loadLogs();
    connectLogsStream();
  } else {
    disconnectLogsStream();
  }
}

async function saveAdminConfig() {
  await api('/api/admin/config', {
    method: 'POST',
    body: {
      devices: state.admin.config.devices,
      publicPresets: state.admin.config.publicPresets
    }
  });
  await loadPublic();
}

function promptDevice(existing) {
  const name = prompt('Device name', existing?.name || '');
  if (name === null) return null;
  const host = prompt('Device host/IP (example: 192.168.1.50)', existing?.host || '');
  if (host === null) return null;
  const portRaw = prompt('Port', String(existing?.port ?? 80));
  if (portRaw === null) return null;
  const port = Number(portRaw);
  return {
    id: existing?.id,
    name: name.trim(),
    host: host.trim(),
    port: Number.isFinite(port) ? port : 80,
    enabled: existing ? !!existing.enabled : true
  };
}

function getEnabledDevices() {
  return (state.admin.config.devices || []).filter((d) => d && d.enabled);
}

async function discoverDevices() {
  setStatus(els.devicesStatus, 'Scanning your network…');
  try {
    const out = await api('/api/admin/discover', { method: 'POST' });
    const found = out.found || [];
    if (!found.length) {
      setStatus(els.devicesStatus, 'No WLED devices found.');
      return;
    }

    // Add any new hosts
    const existingHosts = new Set((state.admin.config.devices || []).map((d) => String(d.host)));
    for (const d of found) {
      if (existingHosts.has(d.host)) continue;
      state.admin.config.devices.push({
        id: crypto.randomUUID?.() || String(Date.now()) + Math.random().toString(16).slice(2),
        name: d.name || d.host,
        host: d.host,
        port: d.port ?? 80,
        enabled: true
      });
    }

    await saveAdminConfig();
    await loadAdminConfig();
    setStatus(els.devicesStatus, `Found ${found.length} device(s).`);
  } catch (e) {
    setStatus(els.devicesStatus, e.message);
  }
}

function renderPresetEditor({ preset }) {
  const enabledDevices = getEnabledDevices();
  const presetsByDeviceId = state.admin.importedPresetsByDeviceId || {};

  const deviceRows = enabledDevices.map((d) => {
    const available = Array.isArray(presetsByDeviceId[d.id]) ? presetsByDeviceId[d.id] : null;
    const current = preset?.devicePresets?.[d.id] ?? '';

    if (available && available.length) {
      const options = [
        `<option value="">(skip)</option>`,
        ...available.map((p) => `<option value="${p.id}" ${String(p.id) === String(current) ? 'selected' : ''}>${escapeHtml(p.name)}</option>`)
      ].join('');

      return `
        <div class="item">
          <div class="meta">
            <div class="title">${escapeHtml(d.name || d.host)}</div>
            <div class="subtitle">${escapeHtml(d.host)}</div>
          </div>
          <div class="controls">
            <select data-device-id="${escapeHtml(d.id)}" class="devicePresetSelect">${options}</select>
          </div>
        </div>
      `;
    }

    return `
      <div class="item">
        <div class="meta">
          <div class="title">${escapeHtml(d.name || d.host)}</div>
          <div class="subtitle">${escapeHtml(d.host)} · Import presets to get a dropdown</div>
        </div>
        <div class="controls">
          <input data-device-id="${escapeHtml(d.id)}" class="devicePresetInput" inputmode="numeric" placeholder="Preset ID" value="${escapeHtml(current)}" />
        </div>
      </div>
    `;
  }).join('');

  els.presetEditor.innerHTML = `
    <h3>${preset ? 'Edit public preset' : 'New public preset'}</h3>
    <div class="grid">
      <label class="field">
        <span>Public preset name</span>
        <input id="publicPresetName" type="text" value="${escapeHtml(preset?.name || '')}" placeholder="Example: Party Mode" />
      </label>
    </div>
    <p class="muted">Choose which WLED preset each enabled device should use.</p>
    <div class="list">${deviceRows || '<div class="muted">No enabled devices.</div>'}</div>
    <div class="actions">
      <button id="savePublicPresetBtn" class="primary" type="button">Save</button>
      <button id="cancelPublicPresetBtn" class="ghost" type="button">Cancel</button>
    </div>
  `;

  els.presetEditor.style.display = 'block';

  document.getElementById('cancelPublicPresetBtn').addEventListener('click', () => {
    state.admin.editingPresetId = null;
    els.presetEditor.style.display = 'none';
    els.presetEditor.innerHTML = '';
  });

  document.getElementById('savePublicPresetBtn').addEventListener('click', async () => {
    const name = String(document.getElementById('publicPresetName').value || '').trim();
    if (!name) {
      setStatus(els.presetsStatus, 'Name is required.');
      return;
    }

    const devicePresets = {};
    for (const sel of Array.from(els.presetEditor.querySelectorAll('.devicePresetSelect'))) {
      const deviceId = sel.dataset.deviceId;
      const v = Number(sel.value);
      if (deviceId && Number.isFinite(v) && v >= 1) devicePresets[deviceId] = v;
    }
    for (const inp of Array.from(els.presetEditor.querySelectorAll('.devicePresetInput'))) {
      const deviceId = inp.dataset.deviceId;
      const v = Number(String(inp.value || '').trim());
      if (deviceId && Number.isFinite(v) && v >= 1) devicePresets[deviceId] = v;
    }

    const id = preset?.id || crypto.randomUUID?.() || String(Date.now());
    const next = { id, name, devicePresets };

    state.admin.config.publicPresets = state.admin.config.publicPresets || [];
    const idx = state.admin.config.publicPresets.findIndex((p) => p && p.id === id);
    if (idx >= 0) state.admin.config.publicPresets[idx] = next;
    else state.admin.config.publicPresets.push(next);

    setStatus(els.presetsStatus, 'Saving…');
    try {
      await saveAdminConfig();
      await loadAdminConfig();
      setStatus(els.presetsStatus, 'Saved.');
      els.presetEditor.style.display = 'none';
      els.presetEditor.innerHTML = '';
    } catch (e) {
      setStatus(els.presetsStatus, e.message);
    }
  });
}

function openPresetEditorById(id) {
  const presets = state.admin.config.publicPresets || [];
  const preset = presets.find((p) => p && p.id === id) || null;
  renderPresetEditor({ preset });
}

function openNewPresetEditor() {
  renderPresetEditor({ preset: null });
}

async function importPresetsAllDevices() {
  const devices = (state.admin.config.devices || []).filter(Boolean);
  if (!devices.length) {
    setStatus(els.devicePresetsStatus, 'Add a device first.');
    return;
  }

  setStatus(els.devicePresetsStatus, 'Importing presets from all devices…');
  try {
    const out = await api('/api/admin/presets/importAll', { method: 'POST' });
    const byId = {};
    for (const d of out.devices || []) {
      byId[d.deviceId] = d.presets || [];
    }
    state.admin.importedPresetsByDeviceId = byId;

    const okCount = (out.devices || []).filter((d) => Array.isArray(d.presets) && d.presets.length).length;
    const errCount = Array.isArray(out.errors) ? out.errors.length : 0;
    setStatus(els.devicePresetsStatus, `Imported from ${okCount} device(s)${errCount ? ` (${errCount} error(s))` : ''}.`);

    // Update device presets view
    renderDevicePresetsDropdown();
    renderDevicePresets();

    // If editor is open, re-render so dropdowns appear
    if (els.presetEditor.style.display !== 'none') {
      const openId = state.admin.editingPresetId;
      if (openId) openPresetEditorById(openId);
    }
  } catch (e) {
    setStatus(els.devicePresetsStatus, e.message);
  }
}

function backupPublicPresets() {
  const presets = state.admin.config.publicPresets || [];
  const data = {
    version: 1,
    exportedAt: new Date().toISOString(),
    publicPresets: presets
  };
  
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `wled-public-presets-backup-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  
  setStatus(els.presetsStatus, `Backed up ${presets.length} preset(s).`);
}

async function restorePublicPresets(file) {
  setStatus(els.presetsStatus, 'Restoring…');
  
  try {
    const text = await file.text();
    const data = JSON.parse(text);
    
    if (!data || !Array.isArray(data.publicPresets)) {
      throw new Error('Invalid backup file format');
    }
    
    const presets = data.publicPresets;
    
    // Validate preset structure
    for (const p of presets) {
      if (!p.id || typeof p.id !== 'string') {
        throw new Error('Invalid preset: missing or invalid id');
      }
      if (!p.name || typeof p.name !== 'string') {
        throw new Error('Invalid preset: missing or invalid name');
      }
    }
    
    // Confirm restore
    const existingCount = (state.admin.config.publicPresets || []).length;
    const msg = existingCount > 0
      ? `This will replace ${existingCount} existing preset(s) with ${presets.length} from backup. Continue?`
      : `Restore ${presets.length} preset(s) from backup?`;
    
    if (!confirm(msg)) {
      setStatus(els.presetsStatus, 'Restore cancelled.');
      return;
    }
    
    state.admin.config.publicPresets = presets;
    await saveAdminConfig();
    await loadAdminConfig();
    
    setStatus(els.presetsStatus, `Restored ${presets.length} preset(s).`);
  } catch (e) {
    setStatus(els.presetsStatus, `Restore failed: ${e.message}`);
  }
}

function bindListActions() {
  if (!hasAdminUi) return;
  els.devicesList.addEventListener('click', async (e) => {
    const btn = e.target.closest('button');
    if (!btn) return;
    const action = btn.dataset.action;
    const id = btn.dataset.id;
    const devices = state.admin.config.devices || [];
    const idx = devices.findIndex((d) => d.id === id);
    if (idx < 0) return;

    if (action === 'toggle') {
      devices[idx].enabled = !devices[idx].enabled;
      await saveAdminConfig();
      renderDevices();
      return;
    }

    if (action === 'edit') {
      const updated = promptDevice(devices[idx]);
      if (!updated) return;
      devices[idx] = updated;
      await saveAdminConfig();
      renderDevices();
      return;
    }

    if (action === 'delete') {
      const ok = confirm('Remove this device?');
      if (!ok) return;
      devices.splice(idx, 1);
      await saveAdminConfig();
      renderDevices();
    }
  });

  els.presetsList.addEventListener('click', async (e) => {
    const btn = e.target.closest('button');
    if (!btn) return;
    const action = btn.dataset.action;
    const id = String(btn.dataset.id || '');
    const presets = state.admin.config.publicPresets || [];
    const idx = presets.findIndex((p) => p && p.id === id);
    if (idx < 0) return;

    if (action === 'applyPreset') {
      const presetId = presets[idx].id;
      setStatus(els.presetsStatus, 'Applying…');
      try {
        await api('/api/apply', { method: 'POST', body: { publicPresetId: presetId } });
        setStatus(els.presetsStatus, 'Applied.');
        setTimeout(() => setStatus(els.presetsStatus, ''), 2000);
      } catch (e) {
        setStatus(els.presetsStatus, e.message);
      }
      return;
    }

    if (action === 'editPreset') {
      state.admin.editingPresetId = presets[idx].id;
      openPresetEditorById(presets[idx].id);
      return;
    }

    if (action === 'setDefault') {
      const presetId = presets[idx].id;
      setStatus(els.presetsStatus, 'Setting default…');
      try {
        await api('/api/admin/settings', {
          method: 'POST',
          body: { 
            defaultPresetId: presetId, 
            revertTimeout: state.admin.config.revertTimeout ?? 0 
          }
        });
        state.admin.config.defaultPresetId = presetId;
        renderPresets();
        renderSettings();
        setStatus(els.presetsStatus, 'Default preset updated.');
        setTimeout(() => setStatus(els.presetsStatus, ''), 2000);
      } catch (e) {
        setStatus(els.presetsStatus, e.message);
      }
      return;
    }

    if (action === 'deletePreset') {
      const ok = confirm('Remove this preset from the public list?');
      if (!ok) return;
      presets.splice(idx, 1);
      await saveAdminConfig();
      renderPresets();
    }
  });
}

function bindUI() {
  if (els.tabs.length) {
    for (const tab of els.tabs) {
      tab.addEventListener('click', () => setActiveTab(tab.dataset.tab));
    }
  }

  if (hasPublicUi) {
    els.refreshBtn.addEventListener('click', loadPublic);
    els.applyBtn.addEventListener('click', applyPreset);
  }

  if (hasAdminUi) {
    // Theme handling
    function getTheme() {
      return localStorage.getItem('theme') || 'system';
    }

    function setTheme(theme) {
      localStorage.setItem('theme', theme);
      document.documentElement.dataset.theme = theme;
      updateThemeButtons();
    }

    function updateThemeButtons() {
      const current = getTheme();
      document.querySelectorAll('.theme-option').forEach(btn => {
        btn.classList.toggle('is-active', btn.dataset.theme === current);
      });
    }

    // Initialize theme
    setTheme(getTheme());

    // Theme option buttons
    document.querySelectorAll('.theme-option').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        setTheme(btn.dataset.theme);
      });
    });

    // Profile menu toggle
    if (els.profileBtn && els.profileDropdown) {
      els.profileBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        els.profileDropdown.classList.toggle('hidden');
      });
      
      // Close dropdown when clicking outside
      document.addEventListener('click', () => {
        els.profileDropdown.classList.add('hidden');
      });
    }

    els.adminLogoutBtn.addEventListener('click', () => {
      (async () => {
        try {
          await api('/api/auth/logout', { method: 'POST' });
        } catch {
          // ignore
        }
        window.location.href = '/login';
      })();
    });

    // Admin tab switching
    for (const tab of els.adminTabs) {
      tab.addEventListener('click', () => setAdminTab(tab.dataset.tab));
    }

    // Logs refresh and filter
    if (els.refreshLogsBtn) {
      els.refreshLogsBtn.addEventListener('click', loadLogs);
    }
    if (els.logsFilter) {
      els.logsFilter.addEventListener('change', renderLogs);
    }

    els.addDeviceBtn.addEventListener('click', async () => {
      const created = promptDevice(null);
      if (!created) return;
      state.admin.config.devices = state.admin.config.devices || [];
      state.admin.config.devices.push({ ...created, id: crypto.randomUUID?.() || created.id || String(Date.now()) });
      await saveAdminConfig();
      renderDevices();
      setStatus(els.devicesStatus, 'Saved.');
    });

    els.discoverBtn.addEventListener('click', discoverDevices);

    els.addPresetBtn.addEventListener('click', async () => {
      state.admin.editingPresetId = null;
      openNewPresetEditor();
    });

    els.devicePresetsSelect.addEventListener('change', () => {
      renderDevicePresets();
    });

    els.importPresetsBtn.addEventListener('click', importPresetsAllDevices);

    els.backupPresetsBtn.addEventListener('click', backupPublicPresets);

    els.restorePresetsBtn.addEventListener('click', () => {
      els.restoreFileInput.click();
    });

    els.restoreFileInput.addEventListener('change', (e) => {
      const file = e.target.files?.[0];
      if (file) {
        restorePublicPresets(file);
        els.restoreFileInput.value = '';
      }
    });

    els.saveSettingsBtn.addEventListener('click', saveSettings);
  }
}

bindUI();
bindListActions();

if (hasPublicUi) {
  loadPublic();
}

if (hasAdminUi) {
  authMe().then((ok) => {
    if (ok) loadAdminConfig();
  });
}
