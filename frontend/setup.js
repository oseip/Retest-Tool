function $(id) { return document.getElementById(id); }

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

async function loadCatalog() {
  const listEl = $('opcoList');
  const errEl = $('setupCatalogError');
  try {
    const resp = await fetch('/api/setup/catalog');
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.detail || 'Failed to load opco catalog');

    if (!data.clients.length) {
      listEl.innerHTML = '<span style="color:var(--text-dim);font-size:12px">No opcos found in the catalog.</span>';
      return;
    }
    listEl.innerHTML = data.clients.map(c => `
      <label class="opco-item">
        <input type="checkbox" value="${escHtml(c.label)}" class="opco-checkbox">
        <span>${escHtml(c.name)}</span>
      </label>
    `).join('');
  } catch (exc) {
    errEl.style.display = 'block';
    errEl.textContent = exc.message;
    listEl.innerHTML = '<span style="color:var(--text-dim);font-size:12px">Unavailable</span>';
    $('setupSubmitBtn').disabled = true;
  }
}

function setStatus(msg, type) {
  const el = $('setupStatus');
  el.style.display = 'block';
  el.style.color = type === 'error' ? 'var(--red)' : 'var(--green)';
  el.textContent = msg;
}

async function handleSubmit(ev) {
  ev.preventDefault();
  const selected = Array.from(document.querySelectorAll('.opco-checkbox:checked')).map(c => c.value);

  if (!selected.length) {
    setStatus('Select at least one opco.', 'error');
    return;
  }

  const body = {
    jira_email: $('jiraEmail').value.trim(),
    jira_api_token: $('jiraToken').value,
    jump_user: $('jumpUser').value.trim(),
    jump_password: $('jumpPassword').value,
    client_labels: selected,
  };

  const btn = $('setupSubmitBtn');
  btn.disabled = true;
  btn.textContent = 'Validating…';
  setStatus('Checking your Jira and jump-server credentials…', 'success');

  try {
    const resp = await fetch('/api/setup/submit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.detail || 'Setup failed');

    setStatus('✅ ' + data.message, 'success');
    showToast(data.message, 'success', 8000);
    document.getElementById('setupForm').querySelectorAll('input, button').forEach(el => el.disabled = true);
  } catch (exc) {
    setStatus(exc.message, 'error');
    showToast(exc.message, 'error');
    btn.disabled = false;
    btn.textContent = 'Save & Validate';
  }
}

document.getElementById('setupForm').addEventListener('submit', handleSubmit);
loadCatalog();
