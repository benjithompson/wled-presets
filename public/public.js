function setStatus(el, msg) {
  if (!el) return;
  el.textContent = msg || '';
}

function escapeHtml(s) {
  return String(s)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
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

const els = {
  presetButtons: document.getElementById('presetButtons'),
  status: document.getElementById('status')
};

let currentPresets = [];
let presetStatus = {}; // Map of preset ID to online status
let currentPresetId = null; // Track currently selected preset
let busy = false;
let lastApplyTime = 0;
const RATE_LIMIT_MS = 1000; // 1 second between selections
const POLL_INTERVAL_MS = 10000; // Poll device status every 10 seconds

function renderPresets() {
  if (!els.presetButtons) return;

  if (!currentPresets.length) {
    els.presetButtons.innerHTML = `<div class="muted">No presets available.</div>`;
    return;
  }

  els.presetButtons.innerHTML = currentPresets
    .map((p) => {
      const name = escapeHtml(p.name || 'Preset');
      const isOffline = presetStatus[p.id] === false;
      const offlineLabel = isOffline ? '<span class="offline-label">OFFLINE</span> ' : '';
      const disabledClass = isOffline ? ' offline' : '';
      return `<button class="presetButton${disabledClass}" type="button" data-id="${escapeHtml(p.id)}" ${isOffline ? 'disabled' : ''}>${offlineLabel}${name}</button>`;
    })
    .join('');
}

function setBusy(next) {
  busy = next;
  for (const btn of Array.from(document.querySelectorAll('.presetButton'))) {
    btn.disabled = busy;
  }
}

async function load() {
  setStatus(els.status, 'Loading…');
  try {
    const cfg = await api('/api/config/public');
    currentPresets = Array.isArray(cfg.publicPresets) ? cfg.publicPresets : [];
    console.log('load: server returned currentPresetId =', cfg.currentPresetId);
    currentPresetId = cfg.currentPresetId || null;
    renderPresets();
    
    // Show glow on currently selected preset (if any)
    if (currentPresetId) {
      const btn = document.querySelector(`.presetButton[data-id="${currentPresetId}"]`);
      if (btn) {
        btn.classList.add('glow-animate');
      }
    }
    
    setStatus(els.status, '');
  } catch (e) {
    renderPresets();
    setStatus(els.status, e.message);
  }
}

async function checkDeviceStatus() {
  try {
    const data = await api('/api/device-status');
    if (data && data.presetStatus) {
      presetStatus = data.presetStatus;
      console.log('checkDeviceStatus: before render, currentPresetId =', currentPresetId);
      renderPresets();
      
      // Re-apply glow to current preset if it exists
      if (currentPresetId) {
        const btn = document.querySelector(`.presetButton[data-id="${currentPresetId}"]`);
        console.log('checkDeviceStatus: re-applying glow to', currentPresetId, 'btn found:', !!btn);
        if (btn && !btn.disabled) {
          btn.classList.add('glow-animate');
        }
      }
    }
  } catch (e) {
    // Silently fail - don't show errors for background polling
    console.error('Failed to check device status:', e);
  }
}

let pollIntervalId = null;

async function startPolling() {
  // Initial check
  await checkDeviceStatus();
  
  // Poll every 10 seconds
  pollIntervalId = setInterval(checkDeviceStatus, POLL_INTERVAL_MS);
}

async function applyPublicPreset(publicPresetId) {
  if (!publicPresetId || busy) return;

  // Rate limit: only allow one selection per second
  const now = Date.now();
  if (now - lastApplyTime < RATE_LIMIT_MS) {
    return;
  }
  lastApplyTime = now;

  // Update current preset ID immediately so polling doesn't reset it
  console.log('applyPublicPreset: setting currentPresetId from', currentPresetId, 'to', publicPresetId);
  currentPresetId = publicPresetId;

  setBusy(true);
  setStatus(els.status, 'Applying…');

  try {
    await api('/api/apply', { method: 'POST', body: { publicPresetId } });
    // Do not show any 'Done.' message
    setStatus(els.status, '');
  } catch (e) {
    setStatus(els.status, e.message);
  } finally {
    setBusy(false);
  }
}


function randomColor() {
  const colors = [
    '#ffb300', '#ff3b3b', '#7ee0b8', '#5b9dff', '#ff6ec7', '#fff176', '#b388ff', '#00e5ff', '#ff4081', '#ffd740'
  ];
  return colors[Math.floor(Math.random() * colors.length)];
}

function createFireworkEffect(btn) {
  const rect = btn.getBoundingClientRect();
  const container = document.createElement('div');
  container.className = 'firework-container';
  container.style.position = 'fixed';
  container.style.left = rect.left + window.scrollX + 'px';
  container.style.top = rect.top + window.scrollY + 'px';
  container.style.width = rect.width + 'px';
  container.style.height = rect.height + 'px';
  container.style.pointerEvents = 'none';
  container.style.zIndex = 9999;

  const numParticles = 18 + Math.floor(Math.random() * 10);
  for (let i = 0; i < numParticles; i++) {
    const particle = document.createElement('div');
    particle.className = 'firework-particle';
    const angle = (2 * Math.PI * i) / numParticles + Math.random() * 0.2;
    const distance = rect.width * (0.5 + Math.random() * 0.7);
    const x = Math.cos(angle) * distance;
    const y = Math.sin(angle) * distance;
    particle.style.background = randomColor();
    particle.style.left = rect.width / 2 + 'px';
    particle.style.top = rect.height / 2 + 'px';
    particle.style.setProperty('--x', x + 'px');
    particle.style.setProperty('--y', y + 'px');
    particle.style.opacity = 0.7 + Math.random() * 0.3;
    container.appendChild(particle);
  }
  document.body.appendChild(container);
  setTimeout(() => {
    container.remove();
  }, 1200 + Math.random() * 800);
}


function setButtonGlow(btn) {
  // Remove glow from all preset buttons
  for (const b of document.querySelectorAll('.presetButton.glow-animate')) {
    b.classList.remove('glow-animate');
  }
  // Remove glow from color wheel
  const colorWheel = document.getElementById('colorWheel');
  if (colorWheel) {
    colorWheel.classList.remove('glow-animate');
    colorWheel.style.removeProperty('--glow-color');
  }
  // Remove active from color wheel segments
  for (const seg of document.querySelectorAll('.color-wheel-segment.active-color')) {
    seg.classList.remove('active-color');
  }
  // Add glow to the selected button
  btn.classList.add('glow-animate');
}

function setColorActive(segment, color) {
  // Remove glow from all preset buttons
  for (const b of document.querySelectorAll('.presetButton.glow-animate')) {
    b.classList.remove('glow-animate');
  }
  // Remove active from all color segments
  for (const seg of document.querySelectorAll('.color-wheel-segment.active-color')) {
    seg.classList.remove('active-color');
  }
  // Add active to selected segment
  segment.classList.add('active-color');
  // Add glow to color wheel with the selected color
  const colorWheel = document.getElementById('colorWheel');
  if (colorWheel) {
    colorWheel.style.setProperty('--glow-color', color);
    colorWheel.classList.add('glow-animate');
  }
  // Clear saved preset since we're using solid color
  currentPresetId = null;
}

function createColorWheelFirework(color) {
  const colorWheel = document.getElementById('colorWheel');
  if (!colorWheel) return;
  
  const rect = colorWheel.getBoundingClientRect();
  const container = document.createElement('div');
  container.className = 'firework-container';
  container.style.position = 'fixed';
  container.style.left = rect.left + 'px';
  container.style.top = rect.top + 'px';
  container.style.width = rect.width + 'px';
  container.style.height = rect.height + 'px';
  container.style.pointerEvents = 'none';
  container.style.zIndex = 9999;

  const numParticles = 18 + Math.floor(Math.random() * 10);
  for (let i = 0; i < numParticles; i++) {
    const particle = document.createElement('div');
    particle.className = 'firework-particle';
    const angle = (2 * Math.PI * i) / numParticles + Math.random() * 0.2;
    const distance = rect.width * (0.5 + Math.random() * 0.7);
    const x = Math.cos(angle) * distance;
    const y = Math.sin(angle) * distance;
    particle.style.background = color;
    particle.style.left = rect.width / 2 + 'px';
    particle.style.top = rect.height / 2 + 'px';
    particle.style.setProperty('--x', x + 'px');
    particle.style.setProperty('--y', y + 'px');
    particle.style.opacity = 0.7 + Math.random() * 0.3;
    container.appendChild(particle);
  }
  document.body.appendChild(container);
  setTimeout(() => {
    container.remove();
  }, 1200 + Math.random() * 800);
}

async function applyColor(hexColor) {
  if (busy) return;

  // Rate limit
  const now = Date.now();
  if (now - lastApplyTime < RATE_LIMIT_MS) {
    return;
  }
  lastApplyTime = now;

  setBusy(true);
  setStatus(els.status, 'Applying…');

  try {
    await api('/api/color', { method: 'POST', body: { color: hexColor } });
    setStatus(els.status, '');
  } catch (e) {
    setStatus(els.status, e.message);
  } finally {
    setBusy(false);
  }
}

document.addEventListener('click', (e) => {
  // Handle color wheel clicks
  const segment = e.target.closest('.color-wheel-segment');
  if (segment) {
    const color = segment.dataset.color;
    if (color) {
      createColorWheelFirework(color);
      setColorActive(segment, color);
      applyColor(color);
    }
    return;
  }

  // Handle preset button clicks
  const btn = e.target.closest('.presetButton');
  if (!btn) return;
  // Firework and persistent glow
  createFireworkEffect(btn);
  setButtonGlow(btn);
  applyPublicPreset(btn.dataset.id);
});

await load();
await startPolling();
