/* ============================================================
   Intake Tab — Nessus → Vulnerability CSV pipeline
   Isolated in this file so the feature can be reverted cleanly.
   ============================================================ */

// ── State ─────────────────────────────────────────────────────────────────
let _intakeFindings   = [];          // current finding list (with _status, _id)
let _intakeEngagement = {};          // engagement settings filled in the form
let _intakeJiraStatus = "idle";      // idle | loading | ready | error
let _intakeJiraCount  = 0;
let _intakeJiraTimer  = null;        // interval for polling index status
let _intakePage       = 0;
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
  _intakePage = 0;
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

function _intakeStartJiraPoll(label) {
  if (_intakeJiraTimer) clearInterval(_intakeJiraTimer);
  _intakeJiraPollCount = 0;
  
  _intakeJiraTimer = setInterval(async () => {
    _intakeJiraPollCount++;
    if (_intakeJiraPollCount > 40) { // 60 seconds max
      clearInterval(_intakeJiraTimer);
      _intakeJiraTimer = null;
      _intakeJiraStatus = 'error';
      _intakeUpdateJiraBar(true);
      return;
    }
    
    try {
      const r = await fetch(`/api/intake/${label}/jira-index-status`);
      if (!r.ok) return;
      const d = await r.json();
      _intakeJiraStatus = d.status;
      _intakeJiraCount  = d.count || 0;
      _intakeUpdateJiraBar();
      if (d.status === 'ready' || d.status === 'error') {
        clearInterval(_intakeJiraTimer);
        _intakeJiraTimer = null;
        // Enable check button if we have findings
        if (d.status === 'ready' && _intakeFindings.length > 0) {
          $('intakeCheckBtn').disabled = false;
        }
      }
    } catch (_) {}
  }, 1500);
}

function _intakeUpdateJiraBar(isTimeout = false) {
  const bar  = $('intakeJiraBar');
  const icon = $('intakeJiraIcon');
  const txt  = $('intakeJiraTxt');
  if (!bar) return;

  if (_intakeJiraStatus === 'loading') {
    icon.textContent = '⏳';
    txt.textContent  = 'Loading Jira tickets…';
    bar.style.color  = 'var(--text-dim)';
  } else if (_intakeJiraStatus === 'ready') {
    icon.textContent = '✅';
    txt.textContent  = `Jira index ready — ${_intakeJiraCount.toLocaleString()} open tickets loaded`;
    bar.style.color  = 'var(--green)';
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

function _intakeResetJiraBar() {
  _intakeJiraStatus = 'idle';
  _intakeJiraCount  = 0;
  _intakeUpdateJiraBar();
}

// ── Nessus folder/scan picker ─────────────────────────────────────────────
let _intakeFolderScans = {};   // folder_id → [scan, ...]

async function _intakeLoadFolders() {
  const label = $('intakeClient').value;
  if (!label) return;
  const folderList  = $('intakeFolderList');
  const scanList    = $('intakeScanList');
  if (!folderList) return;
  folderList.innerHTML = '<span style="color:var(--text-dim)">Loading…</span>';
  folderList.textContent = 'Loading…';
  folderList.style.color = 'var(--text-dim)';
  scanList.textContent   = 'Check a folder to see its scans';
  scanList.style.color   = 'var(--text-dim)';
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
      scanList.innerHTML = '<span style="color:var(--text-dim)">Check a folder to see its scans</span>';
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

    scans.forEach(s => {
      const statusText = s.status === 'completed' ? '' : ` [${s.status}]`;
      const row = document.createElement('label');
      row.dataset.folderSrc = folderId;
      row.style.cssText = 'display:flex;align-items:center;gap:6px;padding:2px 4px;cursor:pointer;font-size:11px';
      const cb2 = document.createElement('input');
      cb2.type = 'checkbox';
      cb2.value = s.id;
      cb2.dataset.scanName = s.name;
      cb2.onchange = _intakeUpdatePullBtn;
      if (s.status !== 'completed') cb2.disabled = true;
      row.appendChild(cb2);
      row.appendChild(document.createTextNode(`${s.name}${statusText}`));
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
  const engagement = _intakeReadEngagement();

  $('intakePullBtn').disabled  = true;
  $('intakePullBtn').textContent = '⏳ Pulling…';
  $('intakeCheckBtn').disabled = true;
  $('intakeExportBtn').disabled = true;
  $('intakeTableWrap').innerHTML = '';
  _intakeSetStatus('Pulling scans… this may take a minute while Nessus generates the export.');

  try {
    const r = await fetch(`/api/intake/${label}/pull`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scan_ids: scanIds, ...engagement }),
    });

    if (!r.ok) {
      const e = await r.json();
      _intakeSetStatus(`❌ Pull failed: ${e.detail || 'Unknown error'}`, true);
      return;
    }

    const d = await r.json();
    _intakeFindings = d.findings || [];
    _intakePage = 0;

    let msg = `✅ Pulled ${_intakeFindings.length.toLocaleString()} findings`;
    if (d.total_raw > d.total_merged) {
      msg += ` (${(d.total_raw - d.total_merged).toLocaleString()} duplicates within scans removed)`;
    }
    if (d.errors && d.errors.length) {
      msg += ` — ⚠️ ${d.errors.length} scan(s) failed: ${d.errors.join('; ')}`;
    }
    _intakeSetStatus(msg);

    _intakeRenderTable();

    // Enable Check Jira only if index is ready
    if (_intakeJiraStatus === 'ready') {
      $('intakeCheckBtn').disabled = false;
    } else {
      _intakeSetStatus(msg + ' — waiting for Jira index…');
    }

  } catch (e) {
    _intakeSetStatus(`❌ ${e.message}`, true);
  } finally {
    _intakeUpdatePullBtn();
    $('intakePullBtn').textContent = '⬇ Pull Scan';
  }
}

// ── Jira dedup check ──────────────────────────────────────────────────────
async function intakeCheckDuplicates() {
  const label = $('intakeClient').value;
  if (!_intakeFindings.length) return;

  $('intakeCheckBtn').disabled  = true;
  $('intakeCheckBtn').textContent = '⏳ Checking…';
  _intakeSetStatus('Checking against Jira…');

  try {
    const r = await fetch(`/api/intake/${label}/check-duplicates`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ findings: _intakeFindings }),
    });

    if (!r.ok) {
      const e = await r.json();
      _intakeSetStatus(`❌ Check failed: ${e.detail || 'Unknown error'}`, true);
      $('intakeCheckBtn').disabled = false;
      $('intakeCheckBtn').textContent = '🔍 Check Jira';
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
      }
    });

    _intakeRenderTable();

    const msg = `🔍 Checked ${_intakeFindings.length} findings against ${(d.jira_tickets_checked || 0).toLocaleString()} Jira tickets — `
              + `${d.new_count} NEW, ${d.duplicate_count} DUPLICATE`;
    _intakeSetStatus(msg);

    $('intakeExportBtn').disabled = d.new_count === 0;

  } catch (e) {
    _intakeSetStatus(`❌ ${e.message}`, true);
  } finally {
    $('intakeCheckBtn').disabled  = false;
    $('intakeCheckBtn').textContent = '🔍 Check Jira';
  }
}

// ── Export ────────────────────────────────────────────────────────────────
async function intakeExport() {
  const newCount = _intakeFindings.filter(f => f._status !== 'duplicate').length;
  if (!newCount) { _intakeSetStatus('No new findings to export', true); return; }

  const engagement = _intakeReadEngagement();

  $('intakeExportBtn').disabled   = true;
  $('intakeExportBtn').textContent = '⏳ Exporting…';

  try {
    const r = await fetch('/api/intake/export', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ findings: _intakeFindings, ...engagement }),
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
    const fnm  = cd.match(/filename=([^\s;]+)/)?.[1] || 'intake.csv';
    a.href = url; a.download = fnm; a.click();
    URL.revokeObjectURL(url);
    _intakeSetStatus(`✅ Exported ${newCount} new findings`);

  } catch (e) {
    _intakeSetStatus(`❌ ${e.message}`, true);
  } finally {
    $('intakeExportBtn').disabled   = false;
    $('intakeExportBtn').textContent = '⬇ Export New Findings';
  }
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

// ── Table render ──────────────────────────────────────────────────────────
function _intakeRenderTable() {
  const wrap = $('intakeTableWrap');
  if (!wrap) return;

  if (!_intakeFindings.length) {
    wrap.innerHTML = '';
    _intakeUpdatePageControls();
    return;
  }

  const total = _intakeFindings.length;
  const start = _intakePage * _INTAKE_PAGE_SIZE;
  const end   = Math.min(start + _INTAKE_PAGE_SIZE, total);
  const page  = _intakeFindings.slice(start, end);

  // Rating → colour
  const RC = {
    critical: 'var(--red)',
    high:     '#e65c00',
    medium:   'var(--yellow)',
    low:      'var(--cyan)',
  };

  let html = `
  <table style="width:100%;border-collapse:collapse;font-size:11px">
    <thead>
      <tr style="background:var(--bg3);border-bottom:1px solid var(--border)">
        <th style="padding:6px 8px;text-align:left;white-space:nowrap">Status</th>
        <th style="padding:6px 8px;text-align:left">Vulnerability Title</th>
        <th style="padding:6px 8px;white-space:nowrap">IP</th>
        <th style="padding:6px 8px;white-space:nowrap">Technology</th>
        <th style="padding:6px 8px;white-space:nowrap">Rating</th>
        <th style="padding:6px 8px;white-space:nowrap">CVSS</th>
        <th style="padding:6px 8px;white-space:nowrap">CVE</th>
        <th style="padding:6px 8px;white-space:nowrap">CIA Damage</th>
        <th style="padding:6px 8px;white-space:nowrap">Risk Value</th>
      </tr>
    </thead>
    <tbody>`;

  page.forEach(f => {
    const rating = (f.Vulnerability_Rating || '').toLowerCase();
    const col    = RC[rating] || 'var(--text-dim)';
    const isDup  = f._status === 'duplicate';
    const isPend = f._status === 'pending';
    const rowStyle = isDup ? 'opacity:0.4' : '';

    const badgeCol  = isDup  ? '#666'               :
                      isPend ? 'var(--text-dim)'     : 'var(--green)';
    const badgeBg   = isDup  ? 'rgba(100,100,100,.15)' :
                      isPend ? 'rgba(150,150,150,.1)'  : 'rgba(0,200,100,.12)';
    const badgeTxt  = isDup  ? 'DUPLICATE' : isPend ? 'PENDING' : 'NEW';

    const dupHint = isDup && f._duplicate_of
      ? `title="Exists in Jira as ${f._duplicate_of}"`
      : '';

    html += `
      <tr style="border-bottom:1px solid var(--border);${rowStyle}" data-fid="${f._id}">
        <td style="padding:5px 8px;white-space:nowrap">
          <span onclick="intakeToggleStatus(${f._id})" ${dupHint}
            style="cursor:pointer;padding:2px 7px;border-radius:10px;font-size:10px;font-weight:600;
                   color:${badgeCol};background:${badgeBg};border:1px solid ${badgeCol};
                   white-space:nowrap">
            ${badgeTxt}
          </span>
        </td>
        <td style="padding:5px 8px;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
            title="${_esc(f.Vulnerability_Title)}">${_esc(f.Vulnerability_Title)}</td>
        <td style="padding:5px 8px;font-family:monospace">${_esc(f.System_IP)}</td>
        <td style="padding:5px 8px;font-family:monospace">${_esc(f.Technology)}</td>
        <td style="padding:5px 8px;color:${col};font-weight:600">${_esc(f.Vulnerability_Rating)}</td>
        <td style="padding:5px 8px">${_esc(f.CVSS)}</td>
        <td style="padding:5px 8px;font-size:10px">${_esc(f.CVE)}</td>
        <td style="padding:5px 8px">
          <input type="text" value="${_esc(f.CIA_Damage)}"
            onchange="_intakeFieldEdit(${f._id},'CIA_Damage',this.value)"
            style="width:100px;background:var(--bg3);border:1px solid var(--border);
                   border-radius:3px;color:var(--text);font-size:11px;padding:2px 4px">
        </td>
        <td style="padding:5px 8px">
          <input type="text" value="${_esc(f.Risk_Value)}"
            onchange="_intakeFieldEdit(${f._id},'Risk_Value',this.value)"
            style="width:72px;background:var(--bg3);border:1px solid var(--border);
                   border-radius:3px;color:var(--text);font-size:11px;padding:2px 4px">
        </td>
      </tr>`;
  });

  html += '</tbody></table>';
  wrap.innerHTML = html;
  _intakeUpdatePageControls();
  _intakeUpdateSummaryBar();
}

function _esc(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function _intakeFieldEdit(id, field, val) {
  const f = _intakeFindings.find(x => x._id === id);
  if (f) f[field] = val;
}

function intakeToggleStatus(id) {
  const f = _intakeFindings.find(x => x._id === id);
  if (!f) return;
  if (f._status === 'duplicate') {
    f._status = 'new';
    f._duplicate_of = null;
  } else if (f._status === 'new') {
    f._status = 'duplicate';
  } else {
    // pending — flip to new
    f._status = 'new';
  }
  // Re-render only the badge for this row (fast)
  const row = document.querySelector(`[data-fid="${id}"]`);
  if (row) {
    const isDup  = f._status === 'duplicate';
    const isPend = f._status === 'pending';
    const badgeCol = isDup  ? '#666'               :
                     isPend ? 'var(--text-dim)'     : 'var(--green)';
    const badgeBg  = isDup  ? 'rgba(100,100,100,.15)' :
                     isPend ? 'rgba(150,150,150,.1)'  : 'rgba(0,200,100,.12)';
    const badgeTxt = isDup  ? 'DUPLICATE' : isPend ? 'PENDING' : 'NEW';
    const badge = row.querySelector('span');
    if (badge) {
      badge.style.color      = badgeCol;
      badge.style.background = badgeBg;
      badge.style.borderColor = badgeCol;
      badge.textContent      = badgeTxt;
    }
    row.style.opacity = isDup ? '0.4' : '';
  }
  _intakeUpdateSummaryBar();
  const newCount = _intakeFindings.filter(x => x._status !== 'duplicate').length;
  $('intakeExportBtn').disabled = newCount === 0;
}

function _intakeUpdateSummaryBar() {
  const bar = $('intakeSummaryBar');
  if (!bar || !_intakeFindings.length) { if (bar) bar.textContent = ''; return; }
  const newCt  = _intakeFindings.filter(f => f._status !== 'duplicate').length;
  const dupCt  = _intakeFindings.filter(f => f._status === 'duplicate').length;
  const pendCt = _intakeFindings.filter(f => f._status === 'pending').length;
  bar.textContent = `Total: ${_intakeFindings.length} | ✅ New: ${newCt} | ⚫ Duplicate: ${dupCt}`
    + (pendCt ? ` | ⏳ Unchecked: ${pendCt}` : '');
}

// ── Pagination ────────────────────────────────────────────────────────────
function _intakeUpdatePageControls() {
  const ctrl = $('intakePageCtrl');
  if (!ctrl) return;
  const total = _intakeFindings.length;
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
  const pages = Math.ceil(_intakeFindings.length / _INTAKE_PAGE_SIZE);
  if (_intakePage < pages - 1) { _intakePage++; _intakeRenderTable(); }
}

// ── Status line ───────────────────────────────────────────────────────────
function _intakeSetStatus(msg, isErr) {
  const el = $('intakeStatus');
  if (!el) return;
  el.textContent = msg;
  el.style.color = isErr ? 'var(--red)' : 'var(--text-dim)';
}
