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
  loginForm: document.getElementById('loginForm'),
  username: document.getElementById('username'),
  password: document.getElementById('password'),
  status: document.getElementById('status'),
  bootstrapCard: document.getElementById('bootstrapCard')
};

// Initialize theme from localStorage
(function initTheme() {
  const theme = localStorage.getItem('theme') || 'system';
  document.documentElement.dataset.theme = theme;
})();

async function loadBootstrapIfNeeded() {
  if (!els.bootstrapCard) return;
  try {
    const st = await api('/api/auth/bootstrap');
    if (!st?.needsBootstrap) {
      els.bootstrapCard.style.display = 'none';
      els.bootstrapCard.innerHTML = '';
      return;
    }

    els.bootstrapCard.style.display = '';
    els.bootstrapCard.innerHTML = `
      <h3>First-time setup</h3>
      <p class="muted">No admin user exists. Create the first admin (localhost only).</p>
      <div class="grid">
        <label class="field">
          <span>New username</span>
          <input id="bootstrapUsername" type="text" autocomplete="username" />
        </label>
        <label class="field">
          <span>New password (min 12 characters)</span>
          <input id="bootstrapPassword" type="password" autocomplete="new-password" />
        </label>
      </div>
      <div class="actions">
        <button id="bootstrapBtn" class="primary" type="button">Create admin</button>
      </div>
      <p id="bootstrapStatus" class="status" role="status"></p>
    `;

    els.bootstrapCard.querySelector('#bootstrapBtn').addEventListener('click', async () => {
      const u = String(els.bootstrapCard.querySelector('#bootstrapUsername').value || '').trim();
      const p = String(els.bootstrapCard.querySelector('#bootstrapPassword').value || '').trim();
      const status = els.bootstrapCard.querySelector('#bootstrapStatus');
      setStatus(status, 'Creating…');
      try {
        await api('/api/auth/bootstrap', { method: 'POST', body: { username: u, password: p } });
        setStatus(status, 'Created. You can now sign in below.');
        els.bootstrapCard.style.display = 'none';
      } catch (e) {
        setStatus(status, e.message);
      }
    });
  } catch {
    // ignore
  }
}

els.loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();

  const username = String(els.username.value || '').trim();
  const password = String(els.password.value || '').trim();

  if (!username || !password) {
    setStatus(els.status, 'Username and password are required.');
    return;
  }

  setStatus(els.status, 'Signing in…');
  try {
    await api('/api/auth/login', { method: 'POST', body: { username, password } });

    const params = new URLSearchParams(window.location.search);
    const redirect = params.get('redirect') || '/admin';
    window.location.href = redirect;
  } catch (e) {
    setStatus(els.status, e.message);
  }
});

await loadBootstrapIfNeeded();
