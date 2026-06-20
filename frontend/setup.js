function $(id) { return document.getElementById(id); }

function toggleSetupTheme() {
  const html = document.documentElement;
  const isLight = html.getAttribute('data-theme') === 'light';
  html.setAttribute('data-theme', isLight ? '' : 'light');
  document.querySelector('[onclick="toggleSetupTheme()"]').textContent = isLight ? '☀️' : '🌙';
}

function escHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function showToast(msg, type = 'info', duration = 5000) {
  const c = $('toastContainer');
  if (!c) return;
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  const icons = { success: '✅', error: '❌', warn: '⚠️', info: 'ℹ️' };
  el.innerHTML = `<span>${icons[type] || 'ℹ️'}</span><span>${escHtml(String(msg))}</span>`;
  c.appendChild(el);
  setTimeout(() => {
    el.classList.add('toast-hiding');
    setTimeout(() => el.remove(), 220);
  }, duration);
}

let _setupRowSeq = 0;
let _nonAxianOpen = false;

function toggleNonAxian() {
  _nonAxianOpen = !_nonAxianOpen;
  $('nonAxianSection').style.display = _nonAxianOpen ? '' : 'none';
  $('nonAxianChevron').style.transform = _nonAxianOpen ? 'rotate(90deg)' : '';
}

// ── Secondary (Non-Axian) client rows ────────────────────────────────────
let _setupSecRowSeq = 0;

function setupSecondaryClientRowHtml() {
  const rowId = `setup-sec-client-${_setupSecRowSeq++}`;
  return `
    <div class="settings-client-row" id="${rowId}">
      <button type="button" class="settings-remove-client" onclick="removeSetupSecClientRow('${rowId}')" title="Remove">✕</button>
      <div class="settings-client-row-grid">
        <div>
          <label>Label (= project key)</label>
          <input type="text" class="text-input su-sc-label" placeholder="CPEL">
        </div>
        <div>
          <label>Display Name</label>
          <input type="text" class="text-input su-sc-name" placeholder="CPEL Project">
        </div>
        <div>
          <label>Kali Port</label>
          <input type="number" class="text-input su-sc-kaliport" value="22">
        </div>
        <div>
          <label>Kali User</label>
          <input type="text" class="text-input su-sc-kaliuser" value="kali">
        </div>
      </div>
      <div class="settings-client-row-grid2">
        <div>
          <label>Kali Password</label>
          <input type="password" class="text-input su-sc-kalipass" placeholder="Kali box password">
        </div>
        <div></div>
        <div>
          <label>Nessus Access Key <span style="font-weight:400;color:var(--text-dim)">(optional)</span></label>
          <input type="password" class="text-input su-sc-nessusaccess">
        </div>
        <div>
          <label>Nessus Secret Key <span style="font-weight:400;color:var(--text-dim)">(optional)</span></label>
          <input type="password" class="text-input su-sc-nessussecret">
        </div>
      </div>
    </div>
  `;
}

function addSetupSecondaryClientRow() {
  $('setupSecondaryClientRows').insertAdjacentHTML('beforeend', setupSecondaryClientRowHtml());
}

function removeSetupSecClientRow(rowId) {
  const row = $(rowId);
  if (row) row.remove();
}

// ── Primary client rows ───────────────────────────────────────────────────
function setupClientRowHtml() {
  const rowId = `setup-client-${_setupRowSeq++}`;
  return `
    <div class="settings-client-row" id="${rowId}">
      <button type="button" class="settings-remove-client" onclick="removeSetupClientRow('${rowId}')" title="Remove client">✕</button>
      <div class="settings-client-row-grid">
        <div>
          <label>Label</label>
          <input type="text" class="text-input su-c-label" placeholder="ClientA">
        </div>
        <div>
          <label>Display Name</label>
          <input type="text" class="text-input su-c-name" placeholder="Client A">
        </div>
        <div>
          <label>Kali Port</label>
          <input type="number" class="text-input su-c-kaliport" value="22">
        </div>
        <div>
          <label>Kali User</label>
          <input type="text" class="text-input su-c-kaliuser" value="kali">
        </div>
      </div>
      <div class="settings-client-row-grid2">
        <div>
          <label>Kali Password</label>
          <input type="password" class="text-input su-c-kalipass" placeholder="Kali box password">
        </div>
        <div></div>
        <div>
          <label>Nessus Access Key <span style="font-weight:400;color:var(--text-dim)">(optional)</span></label>
          <input type="password" class="text-input su-c-nessusaccess">
        </div>
        <div>
          <label>Nessus Secret Key <span style="font-weight:400;color:var(--text-dim)">(optional)</span></label>
          <input type="password" class="text-input su-c-nessussecret">
        </div>
      </div>
    </div>
  `;
}

function addSetupClientRow() {
  $('setupClientRows').insertAdjacentHTML('beforeend', setupClientRowHtml());
}

function removeSetupClientRow(rowId) {
  const row = $(rowId);
  if (row) row.remove();
}

function setStatus(msg, type) {
  const el = $('setupStatus');
  el.style.display = 'block';
  el.style.color = type === 'error' ? 'var(--red)' : 'var(--green)';
  el.textContent = msg;
}

async function handleSubmit(ev) {
  ev.preventDefault();

  const clientRows = Array.from(document.querySelectorAll('.settings-client-row'));
  const clients = clientRows.map(row => {
    const v = sel => row.querySelector(sel).value;
    return {
      label: v('.su-c-label').trim(),
      name: v('.su-c-name').trim(),
      kali_port: parseInt(v('.su-c-kaliport'), 10) || 22,
      kali_user: v('.su-c-kaliuser').trim() || 'kali',
      kali_password: v('.su-c-kalipass'),
      nessus_access_key: v('.su-c-nessusaccess') || null,
      nessus_secret_key: v('.su-c-nessussecret') || null,
    };
  });

  if (!clients.length) {
    setStatus('Add at least one client.', 'error');
    return;
  }
  if (clients.some(c => !c.label)) {
    setStatus('Every client needs a label.', 'error');
    return;
  }
  if (clients.some(c => !c.kali_password)) {
    setStatus('Every client needs a Kali password.', 'error');
    return;
  }

  // ── Non-Axian (secondary) Jira — only included if URL was filled in ──
  const naUrl = $('naJiraUrl').value.trim();
  let jira_secondary = null;
  let clients_secondary = [];

  if (naUrl) {
    const naToken        = $('naJiraToken').value;
    const naRetestStatus = $('naRetestStatus').value.trim() || 'Remediated';
    const naPollInterval = parseInt($('naPollInterval').value, 10) || 300;

    if (!naToken) {
      setStatus('Non-Axian Jira: fill in the Personal Access Token, or leave the URL blank to skip.', 'error');
      return;
    }

    jira_secondary = { url: naUrl, api_token: naToken, retest_status: naRetestStatus, poll_interval: naPollInterval };

    const secRows = Array.from($('setupSecondaryClientRows').querySelectorAll('.settings-client-row'));
    clients_secondary = secRows.map(row => {
      const v = sel => row.querySelector(sel).value;
      return {
        label:             v('.su-sc-label').trim(),
        name:              v('.su-sc-name').trim(),
        kali_port:         parseInt(v('.su-sc-kaliport'), 10) || 22,
        kali_user:         v('.su-sc-kaliuser').trim() || 'kali',
        kali_password:     v('.su-sc-kalipass'),
        nessus_access_key: v('.su-sc-nessusaccess') || null,
        nessus_secret_key: v('.su-sc-nessussecret') || null,
      };
    });

    if (clients_secondary.some(c => !c.label)) {
      setStatus('Non-Axian Jira: every client needs a label.', 'error');
      return;
    }
    if (clients_secondary.some(c => !c.kali_password)) {
      setStatus('Non-Axian Jira: every client needs a Kali password.', 'error');
      return;
    }
  }

  const body = {
    jira_url: $('jiraUrl').value.trim(),
    jira_email: $('jiraEmail').value.trim(),
    jira_api_token: $('jiraToken').value,
    jira_project: $('jiraProject').value.trim(),
    jump_host: $('jumpHost').value.trim(),
    jump_port: parseInt($('jumpPort').value, 10) || 22,
    jump_user: $('jumpUser').value.trim(),
    jump_password: $('jumpPassword').value,
    clients,
    jira_secondary,
    clients_secondary,
  };

  const btn = $('setupSubmitBtn');
  btn.disabled = true;
  btn.textContent = 'Validating…';
  setStatus(`Checking credentials${naUrl ? ' (both Jira instances)' : ''}…`, 'success');

  try {
    const resp = await fetch('/api/setup/submit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.detail || 'Setup failed');

    setStatus('✅ Config saved — activating app…', 'success');
    showToast('Config saved — loading app…', 'success', 4000);
    document.getElementById('setupForm').querySelectorAll('input, button').forEach(el => el.disabled = true);

    // Fire activate in the background — initialising Jira + poller can take
    // a few seconds so we don't await it. The main UI handles a still-booting
    // state gracefully (poll catches up within its first cycle).
    fetch('/api/setup/activate', { method: 'POST' }).catch(() => {});
    setTimeout(() => { window.location.href = '/'; }, 2000);
  } catch (exc) {
    setStatus(exc.message, 'error');
    showToast(exc.message, 'error');
    btn.disabled = false;
    btn.textContent = 'Save & Validate';
  }
}

document.getElementById('setupForm').addEventListener('submit', handleSubmit);
addSetupClientRow();
