/* ============================================================
   Intake Tab — Nessus → Vulnerability CSV pipeline
   Isolated in this file so the feature can be reverted cleanly.
   ============================================================ */

// ── State ─────────────────────────────────────────────────────────────────
let _intakeFindings   = [];          // current finding list (with _status, _id)
let _intakeEngagement = {};          // engagement settings filled in the form
let _intakeJiraStatus = "idle";      // idle | loading | ready | error | cached
let _intakeJiraCount  = 0;
let _intakeJiraUrl    = '';
let _intakeJiraAge    = null;        // seconds since the index was fetched
let _intakeJiraRefreshing = false;   // background refresh in progress
let _intakeJiraTimer  = null;        // interval for polling index status
let _intakePage       = 0;
let _intakeFilter     = 'all';       // all | new | duplicate | pending
let _intakeSearch     = '';
let _intakePendingAutoCheck = false; // auto-run Check Jira when index becomes ready
let _intakeSelectedIds  = new Set(); // finding _id values ticked for export
let _intakeEditId       = null;      // finding open in edit modal

const _INTAKE_RATINGS = ['Critical', 'High', 'Medium', 'Low', 'Info'];
const _INTAKE_PAGE_SIZE = 100;

// ── Init ──────────────────────────────────────────────────────────────────
function initIntakeTab() {
  // Sync client dropdown (already done by _syncClientDropdowns, but make sure)
  const sel = $('intakeClient');
  if (!sel || !sel.value) return;

  // Pre-fetch Jira index as soon as user lands here
  _intakePrefetchJira(sel.value);

  // Load engagement defaults for selected client
  _intakeLoadDefaults(sel.value);

  // Load Nessus folders if SSH connected
  _intakeLoadFolders();

  _intakeLoadIrrelevantConfig();
}

async function _intakeLoadIrrelevantConfig() {
  const ta = $('intakeIrrelevantList');
  if (!ta) return;
  try {
    const r = await fetch('/api/intake/config/irrelevant');
    if (!r.ok) return;
    const d = await r.json();
    ta.value = (d.lines || []).join('\n');
  } catch (_) {}
}

async function intakeSaveIrrelevant() {
  const ta = $('intakeIrrelevantList');
  if (!ta) return;
  const lines = ta.value.split('\n').map(l => l.trim()).filter(Boolean);
  try {
    const r = await fetch('/api/intake/config/irrelevant', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ lines }),
    });
    if (!r.ok) {
      const e = await r.json();
      showToast(e.detail || 'Could not save exclusion list', 'error');
      return;
    }
    const d = await r.json();
    showToast(`Saved ${d.count} excluded vulnerability title(s)`, 'success');
  } catch (e) {
    showToast('Could not save exclusion list: ' + e.message, 'error');
  }
}

async function _intakeLoadDefaults(label) {
  try {
    const r = await fetch(`/api/intake/${label}/engagement-defaults`);
    if (!r.ok) return;
    const d = await r.json();
    _setVal('intakeProjectKey',       d.project_key || '');
    _setVal('intakeTester',           d.tester      || '');
    _setVal('intakeCustomer',         d.customer     || '');
    _setVal('intakeDateStarted',      d.date_started || '');
  } catch (_) {}
}

function _setVal(id, val) {
  const el = $(id);
  if (el && !el.value) el.value = val;  // only set if user hasn't typed
}

// ── Client change ─────────────────────────────────────────────────────────
function onIntakeClientChange() {
  const label = $('intakeClient').value;
  if (!label) return;
  _intakeFindings = [];
  _intakeSelectedIds = new Set();
  _intakePage = 0;
  _intakeFilter = 'all';
  _intakeSearch = '';
  _intakePendingAutoCheck = false;
  const searchEl = $('intakeSearchInput');
  if (searchEl) searchEl.value = '';
  _intakeRenderTable();
  _intakeSetStatus('');
  _intakeResetJiraBar();
  _intakePrefetchJira(label);
  _intakeLoadDefaults(label);
  _intakeLoadFolders();
}

// ── Jira index prefetch ──────────────────────────────────────────────────
async function _intakePrefetchJira(label, force = false) {
  _intakeJiraStatus = "loading";
  _intakeUpdateJiraBar();
  try {
    const url = `/api/intake/${label}/prefetch-jira` + (force ? '?force=1' : '');
    await fetch(url, { method: 'POST' });
  } catch (_) {}
  _intakeStartJiraPoll(label);
}

let _intakeJiraPollCount = 0;

async function _intakeCheckJiraStatus(label) {
  try {
    const r = await fetch(`/api/intake/${label}/jira-index-status`);
    if (!r.ok) return;
    const d = await r.json();
    _intakeJiraStatus  = (d.status === 'cached') ? 'ready' : d.status;
    _intakeJiraCount   = d.count || 0;
    _intakeJiraAge     = d.age_seconds;
    _intakeJiraRefreshing = !!d.refreshing;
    if (d.jira_url) _intakeJiraUrl = d.jira_url;
    _intakeUpdateJiraBar();
    if (d.status === 'ready' || d.status === 'cached' || d.status === 'error') {
      // Keep polling while a background refresh of a cached index is running
      // so the count/age update live when fresh data lands.
      if (!d.refreshing) {
        if (_intakeJiraTimer) clearInterval(_intakeJiraTimer);
        _intakeJiraTimer = null;
      }
      if ((d.status === 'ready' || d.status === 'cached') && _intakeFindings.length > 0) {
        $('intakeCheckBtn').disabled = false;
        if (_intakePendingAutoCheck) {
          _intakePendingAutoCheck = false;
          intakeCheckDuplicates(true);
        }
      }
    }
  } catch (_) {}
}

function _intakeStartJiraPoll(label) {
  if (_intakeJiraTimer) clearInterval(_intakeJiraTimer);
  _intakeJiraPollCount = 0;

  // One shared implementation: _intakeCheckJiraStatus already owns clearing the
  // timer once the index is ready, so the tick just handles the attempt cap.
  const tick = () => {
    // Don't spend requests on a backgrounded tab, and don't let hidden ticks
    // burn through the attempt budget either.
    if (document.hidden) return;
    _intakeJiraPollCount++;
    if (_intakeJiraPollCount > 120) { // ~3 minutes for large clients
      clearInterval(_intakeJiraTimer);
      _intakeJiraTimer = null;
      if (_intakeJiraStatus !== 'ready') {
        _intakeJiraStatus = 'error';
        _intakeUpdateJiraBar(true);
      }
      return;
    }
    _intakeCheckJiraStatus(label);
  };

  // Create the timer before the first check so that check can clear it if the
  // index is already cached.
  _intakeJiraTimer = setInterval(tick, 1500);
  _intakeCheckJiraStatus(label);
}

function _intakeFmtAge(seconds) {
  if (seconds == null) return '';
  const s = Math.max(0, Math.round(seconds));
  if (s < 90)    return 'just now';
  const m = Math.round(s / 60);
  if (m < 90)    return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 36)    return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

function _intakeUpdateJiraBar(isTimeout = false) {
  const bar  = $('intakeJiraBar');
  const icon = $('intakeJiraIcon');
  const txt  = $('intakeJiraTxt');
  const refreshBtn = $('intakeJiraRefreshBtn');
  if (!bar) return;
  if (refreshBtn) refreshBtn.style.display = 'none';

  if (_intakeJiraStatus === 'loading') {
    icon.textContent = '⏳';
    txt.textContent  = 'Loading Jira tickets…';
    bar.style.color  = 'var(--text-dim)';
  } else if (_intakeJiraStatus === 'ready' || _intakeJiraStatus === 'cached') {
    icon.textContent = _intakeJiraRefreshing ? '🔄' : '✅';
    const age = _intakeFmtAge(_intakeJiraAge);
    let msg = `Jira index ready — ${_intakeJiraCount.toLocaleString()} tickets`;
    if (age) msg += ` (cached ${age})`;
    if (_intakeJiraRefreshing) msg += ' — refreshing…';
    txt.textContent  = msg;
    bar.style.color  = 'var(--green)';
    if (refreshBtn && !_intakeJiraRefreshing) refreshBtn.style.display = 'inline';
  } else if (_intakeJiraStatus === 'error') {
    icon.textContent = '⚠️';
    txt.textContent  = isTimeout ? 'Jira index timed out — check connection' : 'Jira index failed — check connection';
    bar.style.color  = 'var(--red)';
    const retry = document.createElement('a');
    retry.textContent = ' (Retry)';
    retry.href = 'javascript:void(0)';
    retry.style.color = 'var(--text)';
    retry.style.marginLeft = '6px';
    retry.onclick = () => _intakePrefetchJira($('intakeClient').value, true);
    txt.appendChild(retry);
  } else {
    icon.textContent = '';
    txt.textContent  = '';
  }
}

async function intakeRefreshJira() {
  const label = $('intakeClient').value;
  if (!label) return;
  _intakeJiraRefreshing = true;
  _intakeUpdateJiraBar();
  try {
    await fetch(`/api/intake/${label}/refresh-jira`, { method: 'POST' });
  } catch (_) {}
  _intakeStartJiraPoll(label);
}

function _intakeResetJiraBar() {
  _intakeJiraStatus = 'idle';
  _intakeJiraCount  = 0;
  _intakeJiraUrl    = '';
  _intakeJiraAge    = null;
  _intakeJiraRefreshing = false;
  _intakeUpdateJiraBar();
}

function _intakeJiraStatusStyle(status) {
  const s = (status || '').toLowerCase();
  if (s === 'fixed') return 'color:var(--green);font-weight:600';
  if (s.includes('not fixed')) return 'color:var(--red);font-weight:600';
  if (s === 'reported' || s === 'open' || s === 'in progress') return 'color:var(--yellow);font-weight:600';
  if (s === 'remediated') return 'color:var(--cyan);font-weight:600';
  return 'color:var(--text);font-weight:600';
}

function _intakeFmtJiraStatus(status) {
  return (status || '').trim() || '—';
}
let _intakeFolderScans = {};   // folder_id → [scan, ...]

function _intakeFmtScanTime(unixSec) {
  if (!unixSec) return '';
  const d = new Date(Number(unixSec) * 1000);
  if (Number.isNaN(d.getTime())) return '';
  return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

async function _intakeLoadFolders() {
  const label = $('intakeClient').value;
  if (!label) return;
  const folderList  = $('intakeFolderList');
  const scanList    = $('intakeScanList');
  if (!folderList) return;
  folderList.textContent = 'Loading…';
  folderList.className = 'intake-picker-list intake-folder-list';
  scanList.innerHTML = '<span class="intake-placeholder">Check a folder to see its scans</span>';
  _intakeFolderScans = {};
  try {
    const r = await fetch(`/api/nessus/${label}/folders`);
    if (!r.ok) {
      const e = await r.json();
      folderList.innerHTML = '';
      const span = document.createElement('span');
      span.style.color = 'var(--red)';
      span.textContent = e.detail || 'Error loading folders';
      folderList.appendChild(span);
      return;
    }
    const d = await r.json();
    const folders = (d.folders || []).filter(f => f.type !== 'trash');
    if (!folders.length) {
      folderList.textContent = 'No folders found';
      return;
    }
    folderList.innerHTML = '';
    folders.forEach(f => {
      const row = document.createElement('label');
      row.style.cssText = 'display:flex;align-items:center;gap:6px;padding:3px 4px;cursor:pointer;font-size:12px';
      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.dataset.folderId = f.id;
      cb.onchange = () => _intakeFolderToggled(cb, f.id, f.name, label);
      row.appendChild(cb);
      row.appendChild(document.createTextNode(`${f.name} (${f.type})`));
      folderList.appendChild(row);
    });
  } catch (e) {
    folderList.innerHTML = '';
    const span = document.createElement('span');
    span.style.color = 'var(--red)';
    span.textContent = e.message;
    folderList.appendChild(span);
  }
}

async function _intakeFolderToggled(cb, folderId, folderName, label) {
  const scanList = $('intakeScanList');
  if (!cb.checked) {
    // Un-check: remove all scans from this folder
    document.querySelectorAll(`[data-folder-src="${folderId}"]`).forEach(el => el.remove());
    delete _intakeFolderScans[folderId];
    if (!scanList.querySelector('label')) {
      scanList.innerHTML = '<span class="intake-placeholder">Check a folder to see its scans</span>';
    }
    _intakeUpdatePullBtn();
    return;
  }

  // Load scans for this folder
  cb.disabled = true;
  try {
    const r = await fetch(`/api/nessus/${label}/scans?folder_id=${folderId}`);
    if (!r.ok) { cb.checked = false; cb.disabled = false; return; }
    const d = await r.json();
    const scans = d.scans || [];
    _intakeFolderScans[folderId] = scans;

    // Clear placeholder
    const ph = scanList.querySelector('span');
    if (ph) ph.remove();

    scans.sort((a, b) => (b.last_modification_date || 0) - (a.last_modification_date || 0));

    scans.forEach(s => {
      const statusText = s.status === 'completed' ? '' : ` [${s.status}]`;
      const hostHint = (s.total_hosts != null && s.total_hosts > 0)
        ? ` (${s.total_hosts} hosts)`
        : '';
      const runAt = _intakeFmtScanTime(s.last_modification_date);
      const row = document.createElement('label');
      row.dataset.folderSrc = folderId;
      row.style.cssText = 'display:flex;align-items:center;gap:8px;padding:3px 4px;cursor:pointer;font-size:11px';
      const cb2 = document.createElement('input');
      cb2.type = 'checkbox';
      cb2.value = s.id;
      cb2.dataset.scanName = s.name;
      cb2.dataset.hosts = s.total_hosts || 0;
      cb2.onchange = _intakeUpdatePullBtn;
      row.appendChild(cb2);
      const nameSpan = document.createElement('span');
      nameSpan.style.cssText = 'flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap';
      nameSpan.textContent = `${s.name}${hostHint}${statusText}`;
      nameSpan.title = s.name;
      row.appendChild(nameSpan);
      if (runAt) {
        const dtSpan = document.createElement('span');
        dtSpan.style.cssText = 'flex-shrink:0;font-size:10px;color:var(--text-dim);white-space:nowrap';
        dtSpan.textContent = runAt;
        dtSpan.title = 'Last scan run';
        row.appendChild(dtSpan);
      }
      scanList.appendChild(row);
    });

    if (!scans.length) {
      const span = document.createElement('span');
      span.dataset.folderSrc = folderId;
      span.style.cssText = 'display:block;color:var(--text-dim);font-size:11px;padding:4px';
      span.textContent = `No scans in "${folderName}"`;
      scanList.appendChild(span);
    }
  } catch (e) {
    cb.checked = false;
  }
  cb.disabled = false;
  _intakeUpdatePullBtn();
}

function _intakeUpdatePullBtn() {
  const checked = document.querySelectorAll('#intakeScanList input[type=checkbox]:checked');
  $('intakePullBtn').disabled = checked.length === 0;
  $('intakePullBtn').textContent = checked.length > 1
    ? `⬇ Pull & Merge ${checked.length} Scans`
    : '⬇ Pull Scan';
}

// ── Pull & merge ──────────────────────────────────────────────────────────
async function intakePull() {
  const label = $('intakeClient').value;
  const checked = Array.from(document.querySelectorAll('#intakeScanList input[type=checkbox]:checked'));
  if (!checked.length) return;

  const scanIds = checked.map(c => parseInt(c.value));
  const scanHostCounts = {};
  checked.forEach(c => { scanHostCounts[parseInt(c.value, 10)] = parseInt(c.dataset.hosts || '0', 10); });
  const maxHosts = Math.max(0, ...Object.values(scanHostCounts));
  const engagement = _intakeReadEngagement();
  const force = !!($('intakeForcePull') && $('intakeForcePull').checked);

  $('intakePullBtn').disabled  = true;
  $('intakePullBtn').textContent = '⏳ Pulling…';
  $('intakeCheckBtn').disabled = true;
  $('intakeExportBtn').disabled = true;
  if ($('intakeExportAllBtn')) $('intakeExportAllBtn').disabled = true;
  if ($('intakeExportSelectedBtn')) $('intakeExportSelectedBtn').disabled = true;
  if ($('intakeCreateBtn')) $('intakeCreateBtn').disabled = true;
  if ($('intakeCreateSelectedBtn')) $('intakeCreateSelectedBtn').disabled = true;
  _intakeSelectedIds = new Set();
  $('intakeTableWrap').innerHTML = '';
  const baseStatus = force
    ? (maxHosts >= 500
      ? 'Pulling large scan(s) from Nessus (forced)… export can take 10–20 min per scan.'
      : 'Pulling scans from Nessus (forced)… export can take 1–4 min per scan.')
    : (maxHosts >= 500
      ? 'Pulling large scan(s)… cached scans load instantly; fresh exports can take 10–20 min.'
      : 'Pulling scans… cached scans load instantly; new ones take 1–4 min while Nessus generates the export.');
  _intakeSetStatus(baseStatus);

  const pullStarted = Date.now();
  const tick = setInterval(() => {
    const sec = Math.round((Date.now() - pullStarted) / 1000);
    _intakeSetStatus(`${baseStatus} (${sec}s elapsed)`);
  }, 5000);

  try {
    const r = await fetch(`/api/intake/${label}/pull`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scan_ids: scanIds, scan_host_counts: scanHostCounts, force, ...engagement }),
    });

    if (!r.ok) {
      const e = await r.json();
      _intakeSetStatus(`❌ Pull failed: ${e.detail || 'Unknown error'}`, true);
      return;
    }

    const d = await r.json();
    _intakeFindings = d.findings || [];
    _intakeSelectedIds = new Set();
    _intakePage = 0;

    let msg = `✅ Pulled ${_intakeFindings.length.toLocaleString()} findings`;
    if (d.total_raw > d.total_merged) {
      msg += ` (${(d.total_raw - d.total_merged).toLocaleString()} duplicates within scans removed)`;
    }
    if (d.excluded_irrelevant) {
      msg += ` — ${d.excluded_irrelevant.toLocaleString()} irrelevant excluded`;
    }
    if (d.cached_scans) {
      msg += ` — ${d.cached_scans} scan(s) from cache`
           + (d.pulled_scans ? `, ${d.pulled_scans} freshly pulled` : '');
    }
    if (d.errors && d.errors.length) {
      msg += ` — ⚠️ ${d.errors.length} scan(s) failed: ${d.errors.join('; ')}`;
    }
    _intakeSetStatus(msg);

    _intakeRenderTable();

    // Duplicate check runs in background so Pull is not blocked on Jira.
    if (_intakeJiraStatus === 'ready') {
      intakeCheckDuplicates(true);
    } else {
      _intakePendingAutoCheck = true;
      _intakeSetStatus(msg + ' — waiting for Jira index, will auto-check duplicates…');
    }

  } catch (e) {
    _intakeSetStatus(`❌ ${e.message}`, true);
  } finally {
    clearInterval(tick);
    _intakeUpdatePullBtn();
    $('intakePullBtn').textContent = '⬇ Pull Scan';
  }
}

// ── Jira dedup check ──────────────────────────────────────────────────────
async function intakeCheckDuplicates(silent = false) {
  const label = $('intakeClient').value;
  if (!_intakeFindings.length) return;

  $('intakeCheckBtn').disabled  = true;
  $('intakeCheckBtn').textContent = '⏳ Checking…';
  if (!silent) _intakeSetStatus('Checking against Jira…');

  try {
    const r = await fetch(`/api/intake/${encodeURIComponent(label)}/check-duplicates`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ findings: _intakeFindings }),
    });

    if (!r.ok) {
      const e = await r.json();
      if (r.status === 503 && !silent) {
        _intakePendingAutoCheck = true;
        _intakeSetStatus(`${e.detail || 'Jira index not ready'} — will retry when ready…`);
      } else if (!silent) {
        _intakeSetStatus(`❌ Check failed: ${e.detail || 'Unknown error'}`, true);
      }
      return;
    }

    const d = await r.json();

    // Merge results back into findings
    const byId = {};
    (d.results || []).forEach(res => { byId[res._id] = res; });
    _intakeFindings.forEach(f => {
      const res = byId[f._id];
      if (res) {
        f._status       = res.status;
        f._duplicate_of = res.duplicate_of;
        f._duplicate_status = res.duplicate_status;
        f._recurrence_of = res.recurrence_of || null;
        f._previous_jira_status = res.previous_jira_status || '';
        f._match_kind   = res.match_kind;
      }
    });

    _intakePage = 0;
    _intakeRenderTable();

    const cveMatches = (d.results || []).filter(x => x.match_kind === 'cve').length;
    const familyMatches = (d.results || []).filter(x => x.match_kind === 'family').length;
    const msg = `🔍 Checked ${_intakeFindings.length} findings against ${(d.jira_tickets_checked || 0).toLocaleString()} Jira tickets — `
              + `${d.new_count} NEW`
              + (d.recurrence_count ? `, ${d.recurrence_count} REOPEN` : '')
              + `, ${d.duplicate_count} DUPLICATE`
              + (familyMatches ? ` (${familyMatches} version-family match)` : '')
              + (cveMatches ? ` (${cveMatches} CVE match)` : '');
    _intakeSetStatus(msg);

    _intakeUpdateExportButtons(d.exportable_count != null ? d.exportable_count : d.new_count);

  } catch (e) {
    if (!silent) _intakeSetStatus(`❌ ${e.message}`, true);
  } finally {
    $('intakeCheckBtn').disabled  = false;
    $('intakeCheckBtn').textContent = '🔍 Check Jira';
  }
}

function _intakeIsExportable(f) {
  if (f._jira_key) return false;
  return f._status !== 'duplicate';
}

function _intakeSelectedExportable() {
  return _intakeFindings.filter(f => _intakeSelectedIds.has(f._id) && _intakeIsExportable(f));
}

// ── Export ────────────────────────────────────────────────────────────────
async function intakeExport(mode = 'new') {
  const allRows = mode === 'all';
  const selected = mode === 'selected';
  const newCount = _intakeFindings.filter(_intakeIsExportable).length;
  const selectedList = _intakeFindings.filter(f => _intakeSelectedIds.has(f._id));

  if (selected && !selectedList.length) {
    _intakeSetStatus('Select at least one finding to export', true);
    return;
  }
  if (!selected && !allRows && !newCount) {
    _intakeSetStatus('No new findings to export', true);
    return;
  }
  if (allRows && !_intakeFindings.length) {
    _intakeSetStatus('No findings to export', true);
    return;
  }

  const engagement = _intakeReadEngagement();
  const btn = selected ? $('intakeExportSelectedBtn')
    : allRows ? $('intakeExportAllBtn') : $('intakeExportBtn');
  const exportFindings = selected ? selectedList : _intakeFindings;

  if (btn) { btn.disabled = true; btn.textContent = '⏳ Exporting…'; }

  try {
    const r = await fetch('/api/intake/export', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        findings: exportFindings,
        export_mode: mode,
        munit_id: $('intakeClient').value || '',
        ...engagement,
      }),
    });

    if (!r.ok) {
      const e = await r.json();
      _intakeSetStatus(`❌ Export failed: ${e.detail || 'Unknown error'}`, true);
      return;
    }

    const blob = await r.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    const cd   = r.headers.get('Content-Disposition') || '';
    const fnm  = cd.match(/filename=([^\s;]+)/)?.[1]
      || (selected ? 'intake_selected.csv' : allRows ? 'intake_full.csv' : 'intake.csv');
    a.href = url; a.download = fnm; a.click();
    URL.revokeObjectURL(url);
    const count = selected ? selectedList.length : allRows ? _intakeFindings.length : newCount;
    const label = selected ? 'selected' : allRows ? 'full report' : 'new';
    _intakeSetStatus(`✅ Exported ${count} finding${count !== 1 ? 's' : ''} (${label})`);

  } catch (e) {
    _intakeSetStatus(`❌ ${e.message}`, true);
  } finally {
    _intakeUpdateExportButtons();
  }
}

// ── Create in Jira ────────────────────────────────────────────────────────
async function intakeCreateJira(mode = 'new') {
  const label = $('intakeClient').value;
  const selected = mode === 'selected';
  const exportableCount = _intakeFindings.filter(_intakeIsExportable).length;
  const selectedList = _intakeSelectedExportable();

  if (selected && !selectedList.length) {
    _intakeSetStatus('Select at least one exportable finding to create in Jira', true);
    return;
  }
  if (!selected && !exportableCount) {
    _intakeSetStatus('No exportable findings to create in Jira', true);
    return;
  }

  const count = selected ? selectedList.length : exportableCount;
  const noun = count === 1 ? 'ticket' : 'tickets';
  if (!confirm(`Create ${count} new Jira ${noun} for ${label}? REOPEN rows become new issues (old tickets are not reopened).`)) {
    return;
  }

  const engagement = _intakeReadEngagement();
  const btn = selected ? $('intakeCreateSelectedBtn') : $('intakeCreateBtn');
  const createFindings = selected ? selectedList : _intakeFindings;

  if (btn) { btn.disabled = true; btn.textContent = '⏳ Creating…'; }

  try {
    const r = await fetch(`/api/intake/${label}/create-jira`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        findings: createFindings,
        create_mode: mode,
        munit_id: label,
        ...engagement,
      }),
    });

    const d = await r.json().catch(() => ({}));
    if (!r.ok) {
      _intakeSetStatus(`❌ Jira create failed: ${d.detail || d.error || 'Unknown error'}`, true);
      return;
    }

    const byId = new Map((d.results || []).map(x => [x._id, x]));
    for (const f of _intakeFindings) {
      const res = byId.get(f._id);
      if (res && res.ok && res.jira_key) {
        f._jira_key = res.jira_key;
        f._jira_url = res.jira_url || `${d.jira_url}/browse/${res.jira_key}`;
      }
    }

    const created = d.created || 0;
    const failed = d.failed || 0;
    let msg = `✅ Created ${created} Jira ticket${created !== 1 ? 's' : ''}`;
    if (failed) msg += ` — ${failed} failed`;
    if (failed && d.results) {
      const err = d.results.find(x => !x.ok);
      if (err && err.error) msg += `: ${err.error.slice(0, 240)}`;
    }
    _intakeSetStatus(msg, failed > 0 && created === 0);
    _intakeRenderTable();
  } catch (e) {
    _intakeSetStatus(`❌ ${e.message}`, true);
  } finally {
    _intakeUpdateExportButtons();
  }
}

function _intakeUpdateExportButtons(newCountOverride, counts) {
  const c = counts || _intakeCounts();
  const newCount = newCountOverride != null ? newCountOverride : c.exportable;
  const selCount = c.selected;
  const selExportable = _intakeSelectedExportable().length;
  const exportBtn = $('intakeExportBtn');
  const exportAllBtn = $('intakeExportAllBtn');
  const exportSelBtn = $('intakeExportSelectedBtn');
  const exportSelCount = $('intakeExportSelectedCount');
  const createBtn = $('intakeCreateBtn');
  const createSelBtn = $('intakeCreateSelectedBtn');
  const createSelCount = $('intakeCreateSelectedCount');

  if (exportBtn) {
    exportBtn.disabled = newCount === 0;
    exportBtn.textContent = '⬇ Export New Findings';
  }
  if (exportAllBtn) {
    exportAllBtn.disabled = !_intakeFindings.length;
    exportAllBtn.textContent = '⬇ Export Full Report';
  }
  if (exportSelBtn) {
    exportSelBtn.disabled = selCount === 0;
    exportSelBtn.innerHTML = `⬇ Export Selected (<span id="intakeExportSelectedCount">${selCount}</span>)`;
  } else if (exportSelCount) {
    exportSelCount.textContent = selCount;
  }
  if (createBtn) {
    createBtn.disabled = newCount === 0;
    createBtn.textContent = '🎫 Create All in Jira';
  }
  if (createSelBtn) {
    createSelBtn.disabled = selExportable === 0;
    createSelBtn.innerHTML = `🎫 Create Selected in Jira (<span id="intakeCreateSelectedCount">${selExportable}</span>)`;
  } else if (createSelCount) {
    createSelCount.textContent = selExportable;
  }
  _intakeUpdateSummaryBar(c);
}

// ── Engagement settings reader ─────────────────────────────────────────────
function _intakeReadEngagement() {
  return {
    impact_type:       $('intakeImpactType').value.trim()       || 'Internal operations impact',
    actor:             $('intakeActor').value.trim()            || 'Unauthenticated user',
    vector:            $('intakeVector').value.trim()           || 'Internal network',
    test_type:         $('intakeTestType').value.trim()         || 'IPT',
    duration:          $('intakeDuration').value.trim()         || '',
    project_key:       $('intakeProjectKey').value.trim()       || '',
    customer:          $('intakeCustomer').value.trim()         || '',
    contact_person:    $('intakeContactPerson').value.trim()    || '',
    technical_contact: $('intakeTechContact').value.trim()      || '',
    purchaser:         $('intakePurchaser').value.trim()        || '',
    tester:            $('intakeTester').value.trim()           || '',
    date_started:      $('intakeDateStarted').value.trim()      || '',
  };
}

// One pass over the findings, shared by the summary bar, filter pills and
// export buttons — each of those used to re-scan the whole list separately,
// so a single render walked the dataset around seven times.
function _intakeCounts() {
  let newCt = 0, dupCt = 0, pendCt = 0, recurrenceCt = 0;
  for (const f of _intakeFindings) {
    if (f._status === 'new') newCt++;
    else if (f._status === 'duplicate') dupCt++;
    else if (f._status === 'pending') pendCt++;
    else if (f._status === 'recurrence') recurrenceCt++;
  }
  return {
    total: _intakeFindings.length,
    new: newCt,
    duplicate: dupCt,
    pending: pendCt,
    recurrence: recurrenceCt,
    exportable: _intakeFindings.filter(_intakeIsExportable).length,
    created: _intakeFindings.filter(f => f._jira_key).length,
    nonDuplicate: _intakeFindings.length - dupCt,
    selected: _intakeSelectedIds.size,
  };
}

// ── Filter / search ───────────────────────────────────────────────────────
function _intakeFilteredFindings() {
  const q = _intakeSearch.trim().toLowerCase();
  return _intakeFindings.filter(f => {
    if (_intakeFilter === 'new' && f._status !== 'new') return false;
    if (_intakeFilter === 'recurrence' && f._status !== 'recurrence') return false;
    if (_intakeFilter === 'duplicate' && f._status !== 'duplicate') return false;
    if (_intakeFilter === 'pending' && f._status !== 'pending') return false;
    if (!q) return true;
    const hay = [
      f.Vulnerability_Title, f.System_IP, f.CVE, f.Technology,
      f._duplicate_of, f.Vulnerability_Rating,
    ].join(' ').toLowerCase();
    return hay.includes(q);
  });
}

function setIntakeFilter(filter) {
  _intakeFilter = filter;
  _intakePage = 0;
  document.querySelectorAll('.intake-filter-pill').forEach(el => {
    el.classList.toggle('active', el.dataset.filter === filter);
  });
  _intakeRenderTable();
}

let _intakeSearchTimer = null;

function setIntakeSearch(val) {
  _intakeSearch = val;
  _intakePage = 0;
  // Debounce: without this every keystroke re-filters the whole finding list
  // and rebuilds the table, which lags badly on large intakes.
  if (_intakeSearchTimer) clearTimeout(_intakeSearchTimer);
  _intakeSearchTimer = setTimeout(() => {
    _intakeSearchTimer = null;
    _intakeRenderTable();
  }, 180);
}

function intakeMarkVisibleNew() {
  _intakeFilteredFindings().forEach(f => {
    f._status = 'new';
    f._duplicate_of = null;
    f._match_kind = null;
  });
  _intakeRenderTable();
  _intakeUpdateExportButtons();
  showToast('Marked visible rows as NEW', 'success');
}

// ── Row selection ─────────────────────────────────────────────────────────
function _intakeCanSelect(f) {
  return _intakeIsExportable(f);
}

function intakeToggleSelect(id, checked) {
  const f = _intakeFindings.find(x => x._id === id);
  if (f && !_intakeCanSelect(f)) return;
  if (checked) _intakeSelectedIds.add(id);
  else _intakeSelectedIds.delete(id);
  const row = document.querySelector(`[data-fid="${id}"]`);
  if (row) row.classList.toggle('intake-row-selected', checked);
  _intakeUpdateExportButtons();
}

function intakeToggleSelectPage(checked) {
  _intakeFilteredFindings()
    .slice(_intakePage * _INTAKE_PAGE_SIZE, (_intakePage + 1) * _INTAKE_PAGE_SIZE)
    .forEach(f => {
      if (!_intakeCanSelect(f)) return;
      if (checked) _intakeSelectedIds.add(f._id);
      else _intakeSelectedIds.delete(f._id);
    });
  _intakeRenderTable();
}

function _intakePageAllSelected(page) {
  const selectable = page.filter(_intakeCanSelect);
  return selectable.length > 0 && selectable.every(f => _intakeSelectedIds.has(f._id));
}

function _intakePageSomeSelected(page) {
  return page.some(f => _intakeCanSelect(f) && _intakeSelectedIds.has(f._id));
}

// ── Table render ──────────────────────────────────────────────────────────
function _intakeRenderTable() {
  const wrap = $('intakeTableWrap');
  const filterBar = $('intakeFilterBar');
  const exportBar = $('intakeExportBar');
  if (!wrap) return;

  if (!_intakeFindings.length) {
    wrap.innerHTML = '';
    if (filterBar) filterBar.style.display = 'none';
    if (exportBar) exportBar.style.display = 'none';
    _intakeUpdatePageControls();
    if ($('intakeSummaryBar')) $('intakeSummaryBar').textContent = '';
    return;
  }

  if (filterBar) filterBar.style.display = 'flex';
  if (exportBar) exportBar.style.display = 'flex';
  const counts = _intakeCounts();
  _intakeUpdateFilterBar(counts);

  const filtered = _intakeFilteredFindings();
  const total = filtered.length;
  const start = _intakePage * _INTAKE_PAGE_SIZE;
  const end   = Math.min(start + _INTAKE_PAGE_SIZE, total);
  const page  = filtered.slice(start, end);
  const pageAllSelected = _intakePageAllSelected(page);
  const pageSomeSelected = !pageAllSelected && _intakePageSomeSelected(page);

  const RC = {
    critical: 'var(--red)',
    high:     '#e65c00',
    medium:   'var(--yellow)',
    low:      'var(--cyan)',
  };

  let html = `
  <table class="intake-table">
    <thead>
      <tr>
        <th class="intake-check-col">
          <input type="checkbox" title="Select all on this page"
            ${pageAllSelected ? 'checked' : ''}
            ${pageSomeSelected ? 'style="opacity:0.6"' : ''}
            onchange="intakeToggleSelectPage(this.checked)">
        </th>
        <th>Status</th>
        <th>Jira</th>
        <th>Vulnerability</th>
        <th>IP</th>
        <th>Tech</th>
        <th>Rating</th>
        <th>CVSS</th>
        <th>CVE</th>
        <th class="intake-cia-col" title="Impact on Confidentiality / Integrity / Availability — click a letter to toggle">CIA Impact</th>
        <th class="intake-risk-col" title="Calculated risk value">Risk</th>
      </tr>
    </thead>
    <tbody>`;

  page.forEach(f => {
    const rating = (f.Vulnerability_Rating || '').toLowerCase();
    const col    = RC[rating] || 'var(--text-dim)';
    const isCreated = !!f._jira_key;
    const isDup  = f._status === 'duplicate';
    const isRec  = f._status === 'recurrence';
    const isPend = f._status === 'pending';
    const isSel  = _intakeSelectedIds.has(f._id);
    const rowCls = (isSel ? 'intake-row-selected ' : '')
      + (isDup ? 'intake-row-dup' : isRec ? 'intake-row-recurrence' : '');

    const badgeCls = isCreated ? 'intake-badge-created'
      : isDup ? 'intake-badge-dup'
      : isRec ? 'intake-badge-recurrence'
      : isPend ? 'intake-badge-pend'
      : 'intake-badge-new';
    const badgeTxt = isCreated ? 'CREATED'
      : isDup ? 'DUPLICATE' : isRec ? 'REOPEN' : isPend ? 'PENDING' : 'NEW';

    const dupHint = isDup && f._duplicate_of
      ? `title="${_esc('Jira: ' + f._duplicate_of + (f._duplicate_status ? ' (' + f._duplicate_status + ')' : ''))}"`
      : isRec && f._recurrence_of
        ? `title="${_esc('Previously ' + f._recurrence_of + ' (' + (f._previous_jira_status || 'Fixed') + ') — upload as new ticket')}"`
        : isCreated
          ? `title="${_esc('Created in Jira: ' + f._jira_key)}"`
          : '';

    const jiraBase = f._jira_url ? f._jira_url.replace(/\/browse\/[^/]+$/, '') : _intakeJiraUrl;
    const jiraKey = isCreated ? f._jira_key : (isDup ? f._duplicate_of : (isRec ? f._recurrence_of : null));
    const jiraCell = jiraKey
      ? (jiraBase
          ? `<a class="intake-jira-key" href="${_esc(jiraBase)}/browse/${_esc(jiraKey)}" target="_blank" rel="noopener">${_esc(jiraKey)}</a>`
          : `<span class="intake-jira-key">${_esc(jiraKey)}</span>`)
      : '';

    const jiraStatusCell = isCreated
      ? 'Created'
      : isDup
        ? _intakeFmtJiraStatus(f._duplicate_status)
        : isRec
          ? `was ${_intakeFmtJiraStatus(f._previous_jira_status || 'Fixed')}`
          : '';

    html += `
      <tr class="${rowCls.trim()}" data-fid="${f._id}">
        <td class="intake-check-col">
          <input type="checkbox" ${isSel ? 'checked' : ''} ${(!isCreated && _intakeCanSelect(f)) ? '' : 'disabled'} onchange="intakeToggleSelect(${f._id}, this.checked)">
        </td>
        <td>
          <span class="intake-badge ${badgeCls}" ${isCreated ? '' : `onclick="intakeToggleStatus(${f._id})"`} ${dupHint}>${badgeTxt}</span>${(isDup || isCreated) ? jiraCell : ''}
        </td>
        <td style="${_intakeJiraStatusStyle(isCreated ? 'Created' : (isDup ? f._duplicate_status : (isRec ? f._previous_jira_status : '')))}">${isRec ? `${_esc(jiraStatusCell)} ${jiraCell}` : (isCreated ? jiraCell : _esc(jiraStatusCell))}</td>
        <td class="intake-cell-title">
          <div class="intake-cell-title-wrap">
            <button type="button" class="intake-edit-btn" title="Edit title, description &amp; recommendation before Jira upload"
              ${(isCreated || isDup) ? 'disabled' : ''} onclick="event.stopPropagation(); intakeOpenEdit(${f._id})">✎</button>
            <span class="intake-cell-title-text${f._edited ? ' edited' : ''}" title="${_esc(f.Vulnerability_Title)}${_esc(f._edited ? ' (edited)' : '')}">${_esc(f.Vulnerability_Title)}</span>
          </div>
        </td>
        <td class="intake-cell-mono">${_esc(f.System_IP)}</td>
        <td class="intake-cell-mono">${_esc(f.Technology)}</td>
        <td style="color:${col};font-weight:600">${_esc(f.Vulnerability_Rating)}</td>
        <td>${_esc(f.CVSS)}</td>
        <td class="intake-cell-cve">${_esc(f.CVE)}</td>
        <td class="intake-cia-col">${_intakeCiaChips(f)}</td>
        <td class="intake-risk-col">
          <input class="intake-cell-input risk" value="${_esc(f.Risk_Value)}"
            style="${_intakeRiskStyle(f.Risk_Value)}"
            title="Risk value (editable)"
            onchange="_intakeRiskEdit(${f._id}, this)"></td>
      </tr>`;
  });

  html += '</tbody></table>';
  wrap.innerHTML = html;
  _intakeUpdatePageControls(filtered.length);
  _intakeUpdateExportButtons(null, counts);   // also refreshes the summary bar
}

function _intakeUpdateSummaryBar(counts) {
  const bar = $('intakeSummaryBar');
  if (!bar || !_intakeFindings.length) { if (bar) bar.textContent = ''; return; }
  const c = counts || _intakeCounts();
  let msg = `Total: ${c.total.toLocaleString()} | ✅ New: ${c.new.toLocaleString()}`;
  if (c.recurrence) msg += ` | 🔁 Reopen: ${c.recurrence.toLocaleString()}`;
  msg += ` | ⚫ Duplicate: ${c.duplicate.toLocaleString()}`;
  if (c.pending) msg += ` | ⏳ Unchecked: ${c.pending.toLocaleString()}`;
  if (c.created) msg += ` | 🎫 In Jira: ${c.created.toLocaleString()}`;
  if (c.selected) msg += ` | ☑ Selected: ${c.selected.toLocaleString()}`;
  bar.textContent = msg;
  const set = (id, v) => { const el = $(id); if (el) el.textContent = v; };
  set('intakeStatTotal', c.total);
  set('intakeStatNew', c.new);
  set('intakeStatDup', c.duplicate);
  set('intakeStatSelected', c.selected);
}

function _intakeUpdateFilterBar(counts) {
  const bar = $('intakeFilterBar');
  if (!bar || !_intakeFindings.length) {
    if (bar) bar.style.display = 'none';
    return;
  }
  bar.style.display = 'flex';
  const c = counts || _intakeCounts();
  const pillCounts = { all: c.total, new: c.new, recurrence: c.recurrence, duplicate: c.duplicate, pending: c.pending };
  bar.querySelectorAll('.intake-filter-pill').forEach(el => {
    const f = el.dataset.filter;
    const cntEl = el.querySelector('.intake-pill-count');
    if (cntEl) cntEl.textContent = pillCounts[f];
    el.classList.toggle('active', f === _intakeFilter);
  });
}

function _esc(s) {
  if (s === null || s === undefined) return '';
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function _intakeFieldEdit(id, field, val) {
  const f = _intakeFindings.find(x => x._id === id);
  if (f) f[field] = val;
}

function _intakeCanEdit(f) {
  return f && !f._jira_key && f._status !== 'duplicate';
}

function intakeOpenEdit(id) {
  const f = _intakeFindings.find(x => x._id === id);
  if (!f || !_intakeCanEdit(f)) return;
  _intakeEditId = id;
  const sub = $('intakeEditSubtitle');
  if (sub) {
    sub.textContent = `${f.System_IP || '—'} · ${f.Technology || '—'} · ${(f._status || 'pending').toUpperCase()}`;
  }
  const titleEl = $('intakeEditTitle');
  const descEl = $('intakeEditDescription');
  const recEl = $('intakeEditRecommendation');
  if (titleEl) titleEl.value = f.Vulnerability_Title || '';
  const ratingEl = $('intakeEditRating');
  if (ratingEl) {
    const r = (f.Vulnerability_Rating || 'Info').trim();
    const match = _INTAKE_RATINGS.find(x => x.toLowerCase() === r.toLowerCase());
    ratingEl.value = match || 'Info';
  }
  if (descEl) descEl.value = f.Vulnerability_Description || '';
  if (recEl) recEl.value = f.Recommendation || '';
  const modal = $('intakeEditModal');
  if (modal) modal.style.display = 'flex';
  if (titleEl) titleEl.focus();
}

function intakeCloseEdit() {
  _intakeEditId = null;
  const modal = $('intakeEditModal');
  if (modal) modal.style.display = 'none';
}

function intakeSaveEdit() {
  if (_intakeEditId == null) return;
  const f = _intakeFindings.find(x => x._id === _intakeEditId);
  if (!f) { intakeCloseEdit(); return; }
  const title = ($('intakeEditTitle')?.value || '').trim();
  if (!title) {
    showToast('Title is required', 'warn');
    $('intakeEditTitle')?.focus();
    return;
  }
  f.Vulnerability_Title = title;
  f.Vulnerability_Description = ($('intakeEditDescription')?.value || '').trim();
  f.Recommendation = ($('intakeEditRecommendation')?.value || '').trim();
  const rating = ($('intakeEditRating')?.value || '').trim();
  if (rating) f.Vulnerability_Rating = rating;
  f._edited = true;
  intakeCloseEdit();
  _intakeRenderTable();
  showToast('Finding updated — changes apply to export & Jira create', 'success');
}

document.addEventListener('keydown', e => {
  if (e.key !== 'Escape') return;
  if ($('intakeEditModal')?.style.display === 'flex') intakeCloseEdit();
});

const _INTAKE_CIA_PARTS = [
  ['C', 'Confidentiality'],
  ['I', 'Integrity'],
  ['A', 'Availability'],
];

function _intakeCiaSet(f) {
  return new Set(
    String(f.CIA_Damage || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean)
  );
}

function _intakeCiaChips(f) {
  const active = _intakeCiaSet(f);
  const chips = _INTAKE_CIA_PARTS.map(([letter, full]) => {
    const on = active.has(full.toLowerCase());
    return `<button type="button" class="intake-cia-chip${on ? ' on' : ''}"
      title="${full}: ${on ? 'affected' : 'not affected'} — click to toggle"
      onclick="intakeToggleCia(${f._id},'${full}',this)">${letter}</button>`;
  }).join('');
  const label = _INTAKE_CIA_PARTS
    .filter(([, full]) => active.has(full.toLowerCase()))
    .map(([, full]) => full)
    .join(', ');
  return `<div class="intake-cia-chips" title="${_esc(label || 'No CIA impact recorded')}">${chips}</div>`;
}

function intakeToggleCia(id, part, btn) {
  const f = _intakeFindings.find(x => x._id === id);
  if (!f) return;
  const active = _intakeCiaSet(f);
  const key = part.toLowerCase();
  if (active.has(key)) active.delete(key); else active.add(key);
  f.CIA_Damage = _INTAKE_CIA_PARTS
    .filter(([, full]) => active.has(full.toLowerCase()))
    .map(([, full]) => full)
    .join(',');
  if (btn) {
    btn.classList.toggle('on');
    const cell = btn.closest('.intake-cia-chips');
    if (cell) cell.title = f.CIA_Damage.split(',').join(', ') || 'No CIA impact recorded';
  }
}

function _intakeRiskStyle(val) {
  const n = parseFloat(val);
  if (isNaN(n)) return '';
  let colour = 'var(--cyan)';
  if (n >= 8) colour = 'var(--red)';
  else if (n >= 6) colour = '#e65c00';
  else if (n >= 4) colour = 'var(--yellow)';
  return `color:${colour}`;
}

function _intakeRiskEdit(id, input) {
  _intakeFieldEdit(id, 'Risk_Value', input.value);
  input.setAttribute('style', _intakeRiskStyle(input.value));
}

function intakeToggleStatus(id) {
  const f = _intakeFindings.find(x => x._id === id);
  if (!f) return;
  if (f._status === 'duplicate') {
    f._status = 'new';
    f._duplicate_of = null;
    f._duplicate_status = '';
  } else if (f._status === 'recurrence') {
    f._status = 'duplicate';
    f._duplicate_of = f._recurrence_of;
    f._duplicate_status = f._previous_jira_status || 'Fixed';
    f._recurrence_of = null;
    f._previous_jira_status = '';
  } else if (f._status === 'new') {
    f._status = 'duplicate';
  } else {
    f._status = 'new';
  }
  _intakeRenderTable();
}

// ── Pagination ────────────────────────────────────────────────────────────
function _intakeUpdatePageControls(filteredTotal) {
  const ctrl = $('intakePageCtrl');
  if (!ctrl) return;
  const total = filteredTotal != null ? filteredTotal : _intakeFilteredFindings().length;
  const pages = Math.ceil(total / _INTAKE_PAGE_SIZE);
  if (pages <= 1) { ctrl.style.display = 'none'; return; }
  ctrl.style.display = 'flex';
  $('intakePageInfo').textContent =
    `Page ${_intakePage + 1} of ${pages} (${total} findings)`;
  $('intakePagePrev').disabled = _intakePage === 0;
  $('intakePageNext').disabled = _intakePage >= pages - 1;
}

function intakePagePrev() {
  if (_intakePage > 0) { _intakePage--; _intakeRenderTable(); }
}

function intakePageNext() {
  const pages = Math.ceil(_intakeFilteredFindings().length / _INTAKE_PAGE_SIZE);
  if (_intakePage < pages - 1) { _intakePage++; _intakeRenderTable(); }
}

// ── Status line ───────────────────────────────────────────────────────────
function _intakeSetStatus(msg, isErr) {
  const el = $('intakeStatus');
  if (!el) return;
  el.textContent = msg;
  el.style.color = isErr ? 'var(--red)' : 'var(--text-dim)';
}
