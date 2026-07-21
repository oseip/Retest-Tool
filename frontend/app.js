'use strict';

// ── State ─────────────────────────────────────────────────────────────────
const state = {
  jobs: {},           // jobId → job object
  selectedJobId: null,
  clientFilter: '',
  statusFilter: '',
  triageFilter: '',
  remExpanded: true,      // collapsed/expanded state of the REMEDIATED pane
  remTypeFilter: 'all',   // 'all' | 'auto' | 'manual'  — remediated section
  remSearch: '',          // search term for remediated section
  manualExpanded: true,
  manualTypeFilter: 'all',
  sweepSearch: '',
  sweepTypeFilter: 'all', // 'all' | 'auto' | 'manual'  — sweep section
  sweepRenderLimit: 100,  // grows as the user scrolls — see _sweepObserver
  checkedIds: new Set(),
  activeStreams: {},  // jobId → EventSource
  lastScanningTime: 0,
};

// ── DOM refs ──────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

// Retest status from config — used to know which not_fixed jobs can transition
let _retestStatus = '';

// Bulk scan tracking — set while a Scan All batch is in progress, null otherwise
let _bulkScan = null; // { total: int, ids: Set<string> }
try {
  const stored = localStorage.getItem('bulkScan');
  if (stored) {
    const parsed = JSON.parse(stored);
    _bulkScan = { total: parsed.total, ids: new Set(parsed.ids) };
  }
} catch (_) {}

function setBulkScan(val) {
  _bulkScan = val;
  try {
    if (_bulkScan) {
      localStorage.setItem('bulkScan', JSON.stringify({ total: _bulkScan.total, ids: Array.from(_bulkScan.ids) }));
    } else {
      localStorage.removeItem('bulkScan');
    }
  } catch (_) {}
}

// Bulk triage tracking — set while a Triage All batch is in progress, null otherwise
let _bulkTriage = null; // { total: int, ids: Set<string> }

// ── Polling ───────────────────────────────────────────────────────────────
async function fetchJobs() {
  try {
    const res = await fetch('/api/jobs');
    if (!res.ok) return;
    const jobs = await res.json(); // slim — heavy fields omitted at scale
    // Replace local state with server truth — removes jobs deleted server-side
    const newJobs = {};
    jobs.forEach(j => {
      const prev = state.jobs[j.id];
      // Preserve heavy fields (output_lines, ticket_description, nmap_command)
      // for jobs whose full detail we've already loaded — the slim list
      // response never includes them, so a plain overwrite would erase them.
      newJobs[j.id] = (prev && prev._full) ? { ...prev, ...j } : j;
    });
    state.jobs = newJobs;
    // Clear selection/checks for jobs that no longer exist
    if (state.selectedJobId && !newJobs[state.selectedJobId]) {
      state.selectedJobId = null;
    }
    state.checkedIds = new Set([...state.checkedIds].filter(id => newJobs[id]));
    // Close stale streams — only the selected scanning job should have one open
    Object.keys(state.activeStreams).forEach(id => {
      const j = newJobs[id];
      if (!j || j.status !== 'scanning' || id !== state.selectedJobId) {
        state.activeStreams[id].close();
        delete state.activeStreams[id];
      }
    });
    renderJobList();
    updateStats();
    // Re-attach stream for the selected job if it dropped (e.g. server restart).
    // Also re-render the detail panel so the terminal element is fresh and the
    // output_lines accumulated so far are visible before new lines arrive.
    const _selJob = state.selectedJobId && newJobs[state.selectedJobId];
    if (_selJob && _selJob.status === 'scanning' && !state.activeStreams[_selJob.id]) {
      openStream(_selJob.id);
      if (!document.getElementById(`terminal-${_selJob.id}`)) {
        // Terminal element gone (user navigated away then back) — re-render detail
        renderDetail(_selJob.id);
      }
    }
  } catch (e) { /* network error, ignore */ }
}

async function fetchClients() {
  try {
    const res = await fetch('/api/clients');
    if (!res.ok) return;
    const clients = await res.json();

    // 1. Update the main dashboard filter (keeps "All Opcos" as first option)
    const sel = $('clientFilter');
    while (sel.options.length > 1) sel.remove(1);
    clients.forEach(c => {
      const opt = document.createElement('option');
      opt.value = c.label;
      opt.textContent = `${c.name} (${c.label})`;
      sel.appendChild(opt);
    });

    // 2. Sync every other tab's client dropdown to the same list
    _syncClientDropdowns(clients);
  } catch (e) { /* ignore */ }
}

function _syncClientDropdowns(clients) {
  // Dropdowns in Report, Assets and Shell tabs that mirror the client list.
  // We rebuild them completely so a session switch always shows the right set.
  ['reportClient', 'weeklyClient', 'duplicatesClient', 'batchClient', 'assetsClient', 'shellClient', 'intakeClient', 'addTicketClient'].forEach(id => {
    const sel = $(id);
    if (!sel) return;
    const prev = sel.value;
    while (sel.options.length > 0) sel.remove(0);
    clients.forEach(c => {
      const o = document.createElement('option');
      o.value = c.label;
      o.textContent = `${c.name} (${c.label})`;
      sel.appendChild(o);
    });
    // Restore prior selection if it still exists in the new list
    if (prev && Array.from(sel.options).some(o => o.value === prev)) {
      sel.value = prev;
    }
  });
}

async function fetchLogs() {
  try {
    const res = await fetch('/api/logs');
    const logs = await res.json();
    const body = $('logsBody');
    body.innerHTML = logs.slice(-100).map(l => `<div>${escHtml(l)}</div>`).join('');
    body.scrollTop = body.scrollHeight;
  } catch (e) { /* ignore */ }
}

async function fetchConfig() {
  try {
    const res = await fetch('/api/config');
    if (!res.ok) return;
    const d = await res.json();
    _retestStatus = d.retest_status || '';
  } catch (e) { /* ignore */ }
}

// ── Render job list ───────────────────────────────────────────────────────
function filteredJobs() {
  return Object.values(state.jobs).filter(j => {
    if (state.clientFilter && j.client_label !== state.clientFilter) return false;
    if (state.statusFilter === 'fixed')        return j.status === 'completed' && j.verdict === 'fixed';
    if (state.statusFilter === 'not_fixed')    return j.status === 'completed' && j.verdict === 'not_fixed';
    if (state.statusFilter === 'inconclusive') return j.status === 'completed' && j.verdict === 'inconclusive';
    if (state.statusFilter && j.status !== state.statusFilter) return false;
    if (state.triageFilter === 'none') { if (j.triage) return false; }
    else if (state.triageFilter && j.triage !== state.triageFilter) return false;
    return true;
  }).sort((a, b) => b.created_at.localeCompare(a.created_at));
}

function triageBadge(j) {
  switch (j.triage) {
    case 'running':   return '<span class="badge-manual" title="Triage in progress">⏳ TRIAGE</span>';
    case 'closed':     return `<span class="badge-updated" title="${escHtml(j.triage_note || '')}">🟢 LIKELY FIXED</span>`;
    case 'open':       return `<span class="badge-manual" title="${escHtml(j.triage_note || '')}" style="background:var(--red,#c0392b)">🔴 STILL OPEN</span>`;
    case 'host_down':  return `<span class="badge-manual" title="${escHtml(j.triage_note || '')}">⚠️ HOST DOWN</span>`;
    case 'error':      return `<span class="badge-manual" title="${escHtml(j.triage_note || '')}">⚠️ TRIAGE ERR</span>`;
    default:           return '';
  }
}

function renderJobCard(j) {
  const icon = statusIcon(j.status, j.verdict);
  const active = j.id === state.selectedJobId ? ' active' : '';
  const checked = state.checkedIds.has(j.id);
  const sevClass = j.ticket_severity ? `sev-${j.ticket_severity.toLowerCase()}` : '';
  const scanning = j.status === 'scanning' ? ' scanning-pulse' : '';
  const vb = (!active && j.verdict) ? ` vborder-${j.verdict}` : '';
  return `
    <div class="job-item${active}${vb}" data-id="${j.id}" onclick="selectJob('${j.id}', event)">
      <input class="job-item-check" type="checkbox" data-id="${j.id}"
             ${checked ? 'checked' : ''}
             onclick="toggleCheck(event,'${j.id}')"
             ${(j.status === 'queued' || j.status === 'error') ? '' : 'disabled'}>
      <div class="job-item-body">
        <div class="job-key">
          ${escHtml(j.ticket_key)}
          ${j.status === 'manual' ? '<span class="badge-manual">🖐 MANUAL</span>' : ''}
          ${j.source === 'manual' ? '<span class="badge-manual">MANUAL</span>' : ''}
          ${j.jira_updated ? '<span class="badge-updated">✓ JIRA</span>' : ''}
          ${triageBadge(j)}
        </div>
        <div class="job-summary" title="${escHtml(j.ticket_summary)}">${escHtml(truncate(j.ticket_summary, 55))}</div>
        <div class="job-meta">
          ${j.ip ? `<span>🌐 ${escHtml(j.ip)}</span>` : ''}
          ${j.port ? `<span>🔌 ${j.port}</span>` : ''}
          ${j.ticket_cvss ? `<span class="${sevClass}">CVSS ${j.ticket_cvss}</span>` : ''}
          <span style="color:var(--text-dim)">${escHtml(j.client_label)}</span>
        </div>
      </div>
      <div class="job-status-icon${scanning}">${icon}</div>
      <button class="job-remove-btn" title="Remove from queue"
              onclick="removeJob('${j.id}',event)">×</button>
    </div>`;
}

function renderJobList() {
  const list = $('jobList');
  const jobs = filteredJobs();

  const remJobs    = jobs.filter(j => j.source !== 'sweep' && j.source !== 'manual');
  const manualJobs = jobs.filter(j => j.source === 'manual');
  const sweepJobs  = jobs.filter(j => j.source === 'sweep');

  if (!jobs.length) {
    list.innerHTML = `<div style="padding:24px;text-align:center;color:var(--text-dim);font-size:12px;">
      No tickets found.<br>Waiting for Jira poll…
    </div>`;
    updateScanSelectedBtn();
    return;
  }

  let html = '';
  if (remJobs.length) {
    const autoRemCount   = remJobs.filter(j => j.status !== 'manual').length;
    const manualRemCount = remJobs.filter(j => j.status === 'manual').length;

    const rtf = state.remTypeFilter;
    let filteredRem = rtf === 'auto'   ? remJobs.filter(j => j.status !== 'manual')
                      : rtf === 'manual' ? remJobs.filter(j => j.status === 'manual')
                      : remJobs;

    if (state.remSearch) {
      const q = state.remSearch.toLowerCase();
      filteredRem = filteredRem.filter(j => 
        (j.ip || '').toLowerCase().includes(q) ||
        (j.ticket_key || '').toLowerCase().includes(q) ||
        (j.ticket_summary || '').toLowerCase().includes(q)
      );
    }

    const remCountLabel = rtf !== 'all'
      ? `${filteredRem.length} of ${remJobs.length}`
      : remJobs.length;

    const remQueuedIds = filteredRem.filter(j => j.status === 'queued' && j.triage !== 'closed').map(j => j.id);
    const allRemChecked = remQueuedIds.length > 0 && remQueuedIds.every(id => state.checkedIds.has(id));

    const remChevron = state.remExpanded ? '▼' : '▶';
    html += `<div class="queue-section-header" style="cursor:pointer" onclick="toggleRemPane()">
      📋 REMEDIATED <span class="section-count">${remCountLabel}</span>
      <div style="display:flex;align-items:center;gap:8px;margin-left:auto" onclick="event.stopPropagation()">
        <label style="display:flex;align-items:center;gap:4px;font-size:10px;font-weight:normal;cursor:pointer;color:var(--text)">
          <input type="checkbox" onchange="toggleSelectAllRem(this.checked, event)" ${allRemChecked ? 'checked' : ''}> Select All
        </label>
      </div>
      <span style="margin-left:8px;font-size:10px;color:var(--text-dim)">${remChevron}</span>
    </div>`;

    if (state.remExpanded) {
      html += `<div class="qfilter-bar">
        <div class="qfilter-group">
          ${_qpill({ label: 'All',       count: remJobs.length, active: rtf === 'all',    onclick: "setRemTypeFilter('all')" })}
          ${_qpill({ label: 'Auto-scan', emoji: '⚡', count: autoRemCount,   active: rtf === 'auto',   onclick: "setRemTypeFilter('auto')" })}
          ${_qpill({ label: 'Manual',    emoji: '🖐', count: manualRemCount, active: rtf === 'manual', onclick: "setRemTypeFilter('manual')" })}
        </div>
        <div class="qfilter-search">
          <input type="text" id="remSearchInput" placeholder="Search IP, Key, or Name…"
                 value="${escHtml(state.remSearch || '')}" oninput="setRemSearch(this.value)">
        </div>
      </div>`;
      html += filteredRem.map(renderJobCard).join('');
    }
  }
  
  if (manualJobs.length) {
    const autoManualCount   = manualJobs.filter(j => j.status !== 'manual').length;
    const manualManualCount = manualJobs.filter(j => j.status === 'manual').length;

    const mtf = state.manualTypeFilter;
    const filteredManual = mtf === 'auto'   ? manualJobs.filter(j => j.status !== 'manual')
                         : mtf === 'manual' ? manualJobs.filter(j => j.status === 'manual')
                         : manualJobs;

    const manualCountLabel = mtf !== 'all'
      ? `${filteredManual.length} of ${manualJobs.length}`
      : manualJobs.length;

    const manualQueuedIds = filteredManual.filter(j => j.status === 'queued' && j.triage !== 'closed').map(j => j.id);
    const allManualChecked = manualQueuedIds.length > 0 && manualQueuedIds.every(id => state.checkedIds.has(id));

    const manualChevron = state.manualExpanded ? '▼' : '▶';
    html += `<div class="queue-section-header" style="cursor:pointer" onclick="toggleManualPane()">
      ➕ MANUAL <span class="section-count">${manualCountLabel}</span>
      <div style="display:flex;align-items:center;gap:8px;margin-left:auto" onclick="event.stopPropagation()">
        <label style="display:flex;align-items:center;gap:4px;font-size:10px;font-weight:normal;cursor:pointer;color:var(--text)">
          <input type="checkbox" onchange="toggleSelectAllManual(this.checked, event)" ${allManualChecked ? 'checked' : ''}> Select All
        </label>
        <button class="btn btn-sm btn-red" style="font-size:11px;padding:2px 7px;margin-left:2px" title="Clear all manual tickets" onclick="clearManualJobs()">🗑</button>
      </div>
      <span style="margin-left:8px;font-size:10px;color:var(--text-dim)">${manualChevron}</span>
    </div>`;

    if (state.manualExpanded) {
      html += `<div class="qfilter-bar">
        <div class="qfilter-group">
          ${_qpill({ label: 'All',       count: manualJobs.length,  active: mtf === 'all',    onclick: "setManualTypeFilter('all')" })}
          ${_qpill({ label: 'Auto-scan', emoji: '⚡', count: autoManualCount,   active: mtf === 'auto',   onclick: "setManualTypeFilter('auto')" })}
          ${_qpill({ label: 'Manual',    emoji: '🖐', count: manualManualCount, active: mtf === 'manual', onclick: "setManualTypeFilter('manual')" })}
        </div>
      </div>`;
      html += filteredManual.map(renderJobCard).join('');
    }
  }
  let hasMoreSweep = false;
  if (sweepJobs.length) {
    // --- counts for the type filter pills ---
    const autoCount          = sweepJobs.filter(j => j.status !== 'manual').length;
    const manualCount        = sweepJobs.filter(j => j.status === 'manual').length;
    const fixedCount         = sweepJobs.filter(j => j.status === 'completed' && j.verdict === 'fixed').length;
    const notFixedCount      = sweepJobs.filter(j => j.status === 'completed' && j.verdict === 'not_fixed').length;
    const inconclusiveCount  = sweepJobs.filter(j => j.status === 'completed' && j.verdict === 'inconclusive').length;

    // --- apply type filter ---
    const tf = state.sweepTypeFilter;
    const typeFiltered = tf === 'auto'         ? sweepJobs.filter(j => j.status !== 'manual')
                       : tf === 'manual'       ? sweepJobs.filter(j => j.status === 'manual')
                       : tf === 'fixed'        ? sweepJobs.filter(j => j.status === 'completed' && j.verdict === 'fixed')
                       : tf === 'not_fixed'    ? sweepJobs.filter(j => j.status === 'completed' && j.verdict === 'not_fixed')
                       : tf === 'inconclusive' ? sweepJobs.filter(j => j.status === 'completed' && j.verdict === 'inconclusive')
                       : sweepJobs;

    // --- apply text search ---
    const q = state.sweepSearch.toLowerCase();
    const filteredSweep = q
      ? typeFiltered.filter(j =>
          `${j.ip || ''} ${j.ticket_key} ${j.ticket_summary} ${j.rule_name || ''}`.toLowerCase().includes(q))
      : typeFiltered;

    const visibleSweep = filteredSweep.slice(0, state.sweepRenderLimit);
    hasMoreSweep = filteredSweep.length > visibleSweep.length;
    const countLabel = (q || tf !== 'all')
      ? `${filteredSweep.length} of ${sweepJobs.length}`
      : sweepJobs.length;

    const sweepQueuedIds = filteredSweep.filter(j => j.status === 'queued' && j.triage !== 'closed').map(j => j.id);
    const allSweepChecked = sweepQueuedIds.length > 0 && sweepQueuedIds.every(id => state.checkedIds.has(id));

    html += `<div class="queue-section-header sweep-section">⟳ SWEEP <span class="section-count">${countLabel}</span>
      <div style="display:flex;align-items:center;gap:8px;margin-left:auto" onclick="event.stopPropagation()">
        <label style="display:flex;align-items:center;gap:4px;font-size:10px;font-weight:normal;cursor:pointer;color:var(--text)">
          <input type="checkbox" onchange="toggleSelectAllSweep(this.checked, event)" ${allSweepChecked ? 'checked' : ''}> Select All
        </label>
        <button class="btn btn-sm btn-red" style="font-size:11px;padding:2px 7px;margin-left:2px" title="Clear all sweep tickets" onclick="clearSweepJobs()">🗑</button>
      </div>
    </div>`;
    html += `<div class="qfilter-bar">
      <div class="qfilter-search full">
        <input id="sweepSearchInput" type="text" placeholder="Filter sweep tickets…" autocomplete="off"
               value="${escHtml(state.sweepSearch)}">
      </div>
      <div class="qfilter-group">
        ${_qpill({ label: 'All',       count: sweepJobs.length, active: tf === 'all',    onclick: "setSweepTypeFilter('all')" })}
        ${_qpill({ label: 'Auto-scan', emoji: '⚡', count: autoCount,   active: tf === 'auto',   onclick: "setSweepTypeFilter('auto')" })}
        ${_qpill({ label: 'Manual',    emoji: '🖐', count: manualCount, active: tf === 'manual', onclick: "setSweepTypeFilter('manual')" })}
        ${fixedCount        ? _qpill({ label: 'Fixed',        emoji: '✅', count: fixedCount,        active: tf === 'fixed',        onclick: "setSweepTypeFilter('fixed')",        flavor: 'fixed' })    : ''}
        ${notFixedCount     ? _qpill({ label: 'Not Fixed',    emoji: '❌', count: notFixedCount,     active: tf === 'not_fixed',    onclick: "setSweepTypeFilter('not_fixed')",    flavor: 'notfixed' }) : ''}
        ${inconclusiveCount ? _qpill({ label: 'Inconclusive', emoji: '⚪', count: inconclusiveCount, active: tf === 'inconclusive', onclick: "setSweepTypeFilter('inconclusive')", flavor: 'incl' })     : ''}
      </div>
    </div>`;
    if (visibleSweep.length) {
      html += visibleSweep.map(renderJobCard).join('');
      if (hasMoreSweep) {
        html += `<div id="sweepLoadMoreSentinel" style="padding:14px;text-align:center;color:var(--text-dim);font-size:11px;display:flex;align-items:center;justify-content:center;gap:8px">
          <span class="spinner-sm"></span> Loading more tickets…
        </div>`;
      }
    } else {
      html += `<div style="padding:14px;text-align:center;color:var(--text-dim);font-size:11px">No sweep tickets match the current filter</div>`;
    }
  }

  // Capture focus state before replacing DOM
  const wasSweepSearchFocused = document.activeElement?.id === 'sweepSearchInput';
  const wasRemSearchFocused = document.activeElement?.id === 'remSearchInput';

  // Preserve scroll position
  const prevScroll = list.scrollTop;
  list.innerHTML = html;
  list.scrollTop = prevScroll;
  updateScanSelectedBtn();
  updateScanAllBtn();

  // Re-attach sweep search listener (input is re-created each render)
  const si = document.getElementById('sweepSearchInput');
  if (si) {
    si.addEventListener('input', e => {
      state.sweepSearch = e.target.value;
      state.sweepRenderLimit = 100; // new filter — start back at the top
      renderJobList();
    });
    if (wasSweepSearchFocused) {
      si.focus();
      si.setSelectionRange(si.value.length, si.value.length);
    }
  }

  const rsi = document.getElementById('remSearchInput');
  if (rsi && wasRemSearchFocused) {
    rsi.focus();
    rsi.setSelectionRange(rsi.value.length, rsi.value.length);
  }

  // Infinite scroll: when the sentinel at the bottom of the rendered sweep
  // list scrolls into view, render the next batch instead of hard-capping
  // at SWEEP_RENDER_LIMIT (the old behavior just told you to filter further).
  if (hasMoreSweep) {
    const sentinel = document.getElementById('sweepLoadMoreSentinel');
    if (sentinel) observeSweepSentinel(sentinel);
  }
}

function setRemTypeFilter(type) {
  state.remTypeFilter = type;
  renderJobList();
}

function setRemSearch(query) {
  state.remSearch = query;
  renderJobList();
}

function toggleRemPane() {
  state.remExpanded = !state.remExpanded;
  renderJobList();
}

function setManualTypeFilter(type) {
  state.manualTypeFilter = type;
  renderJobList();
}

function toggleManualPane() {
  state.manualExpanded = !state.manualExpanded;
  renderJobList();
}

function setSweepTypeFilter(type) {
  state.sweepTypeFilter  = type;
  state.sweepRenderLimit = 100;
  renderJobList();
}

let _sweepObserver = null;
let _loadingMoreSweep = false;

function observeSweepSentinel(sentinel) {
  if (!_sweepObserver) {
    _sweepObserver = new IntersectionObserver(entries => {
      if (_loadingMoreSweep) return;
      if (entries.some(e => e.isIntersecting)) {
        _loadingMoreSweep = true;
        // Brief delay so the spinner is actually visible — the render itself
        // is instant since all jobs are already in memory client-side.
        setTimeout(() => {
          state.sweepRenderLimit += 100;
          _loadingMoreSweep = false;
          renderJobList();
        }, 200);
      }
    }, { root: $('jobList'), rootMargin: '80px', threshold: 0 });
  } else {
    _sweepObserver.disconnect();
  }
  _sweepObserver.observe(sentinel);
}

function statusIcon(status, verdict) {
  if (status === 'queued')   return '⏳';
  if (status === 'scanning') return '🔍';
  if (status === 'error')    return '💥';
  if (status === 'manual')   return '🖐';
  if (status === 'completed') {
    if (verdict === 'fixed')       return '✅';
    if (verdict === 'not_fixed')   return '❌';
    if (verdict === 'inconclusive')return '⚠️';
  }
  return '❓';
}

function updateStats() {
  const all = Object.values(state.jobs);
  $('statQueued').textContent   = `⏳ ${all.filter(j => j.status === 'queued').length}`;
  $('statScanning').textContent = `🔍 ${all.filter(j => j.status === 'scanning').length}`;
  $('statDone').textContent     = `✅ ${all.filter(j => j.status === 'completed').length}`;
  $('statErr').textContent      = `❌ ${all.filter(j => j.status === 'error').length}`;

  const isScanning = all.some(j => j.status === 'scanning');
  if (isScanning) {
    state.lastScanningTime = Date.now();
  }

  const stopBtn = $('stopAllBtn');
  if (stopBtn) {
    // Show stop button if bulk scan is active, if any job is scanning, or if it was recently scanning and there are still queued jobs (avoids flickering during fast job transitions)
    const hasActiveScan = _bulkScan || isScanning || (Date.now() - state.lastScanningTime < 8000 && all.some(j => j.status === 'queued'));
    if (hasActiveScan) {
      stopBtn.style.display = '';
    } else {
      stopBtn.style.display = 'none';
    }
  }

  updateTransitionReadyBtn();
  updateScanAllBtn();
  updateVerdictStats();
  if (_bulkScan) updateBulkProgress();
}

function updateTransitionReadyBtn() {
  const all = Object.values(state.jobs);
  const ready = all.filter(j => {
    if (j.status !== 'completed' || j.jira_updated) return false;
    if (j.verdict === 'fixed') return true;
    // not_fixed: only tickets that were in the Remediated/retest status get transitioned to Not Fixed
    // (open + not_fixed = no Jira action needed)
    if (j.verdict === 'not_fixed' && _retestStatus && j.ticket_status === _retestStatus) return true;
    return false;
  }).length;
  const btn = $('transitionReadyBtn');
  if (ready > 0) {
    btn.style.display = '';
    btn.textContent = `⚡ Transition Ready (${ready})`;
  } else {
    btn.style.display = 'none';
  }
}

// ── Toast notifications ────────────────────────────────────────────────────
function showToast(msg, type = 'info', duration = 4000) {
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

// ── Verdict stats bar ──────────────────────────────────────────────────────
function updateVerdictStats() {
  const all  = Object.values(state.jobs);
  const done = all.filter(j => j.status === 'completed');
  const bar  = $('verdictStats');
  if (!bar) return;
  if (!done.length) { bar.style.display = 'none'; return; }
  const fixed   = done.filter(j => j.verdict === 'fixed').length;
  const nf      = done.filter(j => j.verdict === 'not_fixed').length;
  const inconcl = done.filter(j => j.verdict === 'inconclusive').length;
  const pending = all.filter(j => j.status === 'queued' || j.status === 'scanning').length;
  bar.style.display = '';
  bar.innerHTML =
    `<span class="vs-fixed">✅ ${fixed} Fixed</span>` +
    `<span class="vs-sep">·</span>` +
    `<span class="vs-nf">❌ ${nf} Not Fixed</span>` +
    `<span class="vs-sep">·</span>` +
    `<span class="vs-incl">⚠️ ${inconcl} Inconclusive</span>` +
    (pending ? `<span class="vs-sep">·</span><span class="vs-dim">${pending} pending</span>` : '');
}

// ── Scan All ───────────────────────────────────────────────────────────────
function updateScanAllBtn() {
  if (_bulkScan) {
    updateBulkProgress();
  } else {
    // Excludes triage="closed" — for most rules a closed port still parses to
    // "inconclusive" in the full scan too, so bulk-scanning them just burns the
    // per-job SSH/PTY overhead for no new verdict. Scan them individually if needed.
    const count = filteredJobs().filter(j => (j.status === 'queued' || j.status === 'error') && j.triage !== 'closed').length;
    const btn = $('scanAllBtn');
    if (btn) {
      if (count > 0) {
        btn.style.visibility = '';
        btn.textContent = `▶▶ Scan All (${count})`;
        btn.disabled = false;
        btn.onclick = scanAll;
      } else {
        btn.style.visibility = 'hidden';
        btn.disabled = true;
      }
    }
  }

  if (_bulkTriage) {
    updateTriageProgress();
  } else {
    const triageCount = filteredJobs().filter(j => j.status === 'queued' && !j.triage).length;
    const triageBtn = $('triageAllBtn');
    if (triageBtn) {
      if (triageCount > 0) {
        triageBtn.style.display = '';
        triageBtn.textContent = `⚡ Triage All (${triageCount})`;
        triageBtn.disabled = false;
      } else {
        triageBtn.style.display = 'none';
        triageBtn.disabled = true;
      }
    }
    const stopTriageBtn = $('stopTriageBtn');
    if (stopTriageBtn) stopTriageBtn.style.display = 'none';
  }

  // Respects the client filter (so the button matches what's currently in view)
  // but not the triage filter — it always targets the full likely-fixed set.
  const likelyFixedCount = Object.values(state.jobs).filter(j =>
    j.status === 'queued' && j.triage === 'closed' &&
    (!state.clientFilter || j.client_label === state.clientFilter)
  ).length;
  const triageTransitionBtn = $('triageTransitionBtn');
  if (triageTransitionBtn) {
    if (likelyFixedCount > 0) {
      triageTransitionBtn.style.display = '';
      triageTransitionBtn.textContent = `🟢 Transition Likely Fixed (${likelyFixedCount})`;
    } else {
      triageTransitionBtn.style.display = 'none';
    }
  }
}

// ── Triage bulk transition ──────────────────────────────────────────────────
async function openTriageTransitionModal() {
  $('triageTransitionPreviewBody').innerHTML = '<span style="color:var(--text-dim)">⏳ Loading…</span>';
  $('triageTransitionTicketList').style.display = 'none';
  $('triageTransitionTicketList').innerHTML = '';
  $('triageModalComment').value = '';
  $('triageTransitionConfirmBtn').disabled = true;
  $('triageTransitionModal').style.display = 'flex';

  try {
    const qs  = state.clientFilter ? `?client_label=${encodeURIComponent(state.clientFilter)}` : '';
    const res = await fetch(`/api/jobs/triage-transition-preview${qs}`);
    const data = await res.json();
    const total = data.to_fixed.length;

    if (total === 0) {
      $('triageTransitionPreviewBody').innerHTML =
        '<span style="color:var(--text-dim)">No likely-fixed tickets to transition.</span>';
      return;
    }

    $('triageTransitionPreviewBody').innerHTML =
      `<div style="color:var(--green)">🟢 <b>${total}</b> ticket${total!==1?'s':''} → <b>Fixed</b> (port closed, no full scan run)</div>`;

    $('triageTransitionTicketList').innerHTML = data.to_fixed.map(t => `
      <div style="display:flex;align-items:center;gap:8px;padding:6px 10px;border-bottom:1px solid var(--border);font-size:11px">
        <span>🟢</span>
        <span style="font-weight:600;white-space:nowrap">${escHtml(t.ticket_key)}</span>
        <span style="flex:1;color:var(--text-dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(truncate(t.ticket_summary, 55))}</span>
        <span style="color:var(--text-dim);white-space:nowrap">${escHtml(t.client_label)}</span>
      </div>`).join('');
    $('triageTransitionTicketList').style.display = '';
    $('triageTransitionConfirmBtn').disabled = false;
    $('triageTransitionConfirmBtn').textContent = `Transition ${total} Ticket${total!==1?'s':''}`;
  } catch (e) {
    $('triageTransitionPreviewBody').innerHTML = `<span style="color:var(--red)">⚠️ ${escHtml(e.message)}</span>`;
  }
}

function closeTriageTransitionModal() {
  $('triageTransitionModal').style.display = 'none';
}

async function runTriageBulkTransition() {
  const btn = $('triageTransitionConfirmBtn');
  btn.disabled = true;
  btn.textContent = 'Transitioning…';
  const comment = $('triageModalComment').value.trim();
  try {
    const res = await fetch('/api/jobs/triage-transition-bulk', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_label: state.clientFilter || null,
        comment: comment || null,
      }),
    });
    const data = await res.json();
    closeTriageTransitionModal();
    await fetchJobs();
    const ok   = data.succeeded.length;
    const fail = data.failed.length;
    if (fail === 0) {
      showToast(`${ok} ticket${ok!==1?'s':''} transitioned to Fixed`, 'success', 5000);
    } else {
      const firstErr = data.failed[0]?.error || 'unknown error';
      showToast(`${ok} transitioned · ${fail} failed: ${firstErr}`, 'warn', 9000);
    }
  } catch (e) {
    showToast(e.message, 'error');
    btn.disabled = false;
  }
}

async function triageAll() {
  const ids = filteredJobs().filter(j => j.status === 'queued' && !j.triage).map(j => j.id);
  if (!ids.length) return;
  const btn = $('triageAllBtn');
  if (btn) { btn.disabled = true; btn.textContent = 'Starting…'; }
  showToast(`Triaging ${ids.length} ticket${ids.length !== 1 ? 's' : ''}…`, 'info', 2500);

  const results = await Promise.allSettled(
    ids.map(id => fetch(`/api/jobs/${id}/triage`, { method: 'POST' }))
  );
  let ok = 0, fail = 0;
  const startedIds = new Set();
  results.forEach((r, i) => {
    if (r.status === 'fulfilled' && r.value.ok) { startedIds.add(ids[i]); ok++; }
    else fail++;
  });

  if (ok > 0) _bulkTriage = { total: ok, ids: startedIds };
  if (fail > 0) showToast(`${ok} started · ${fail} failed to start`, 'warn');
  updateScanAllBtn();
}

// ── Bulk triage progress ────────────────────────────────────────────────────
function updateTriageProgress() {
  const stopBtn = $('stopTriageBtn');
  const triageAllBtn = $('triageAllBtn');
  if (!_bulkTriage) {
    if (stopBtn) stopBtn.style.display = 'none';
    return;
  }

  let done = 0;
  _bulkTriage.ids.forEach(id => {
    const j = state.jobs[id];
    // A triage job counts as done once it has a result and isn't still running
    if (!j || (j.triage && j.triage !== 'running')) done++;
  });

  const total = _bulkTriage.total;

  if (triageAllBtn) {
    triageAllBtn.style.display = '';
    triageAllBtn.disabled = true;
    triageAllBtn.textContent = `⏳ ${done} / ${total} triaged`;
  }
  if (stopBtn) stopBtn.style.display = '';

  if (done >= total) {
    _bulkTriage = null;
    if (stopBtn) stopBtn.style.display = 'none';
    showToast(`Triage complete — ${done} ticket${done !== 1 ? 's' : ''} checked`, 'success', 4000);
    updateScanAllBtn(); // Restore normal button state
  }
}

async function stopAllTriage() {
  const stopBtn = $('stopTriageBtn');
  if (stopBtn) { stopBtn.disabled = true; stopBtn.textContent = 'Stopping…'; }
  try {
    const qs = state.clientFilter ? `?client_label=${encodeURIComponent(state.clientFilter)}` : '';
    const res = await fetch(`/api/jobs/stop-triage${qs}`, { method: 'POST' });
    const data = await res.json();
    _bulkTriage = null;
    if (stopBtn) { stopBtn.style.display = 'none'; stopBtn.disabled = false; stopBtn.textContent = '⏹ Stop Triage'; }
    showToast(`Stopped ${data.cancelled_triage} pending triage check${data.cancelled_triage !== 1 ? 's' : ''} — already-running check finishes naturally`, 'warn', 6000);
    await fetchJobs();
  } catch (e) {
    if (stopBtn) { stopBtn.disabled = false; stopBtn.textContent = '⏹ Stop Triage'; }
    showToast('Failed to stop triage', 'error');
  }
  updateScanAllBtn();
}

// ── Bulk scan progress ─────────────────────────────────────────────────────
function updateBulkProgress() {
  const stopBtn = $('stopAllBtn');
  const scanAllBtn = $('scanAllBtn');
  if (!_bulkScan) {
    if (stopBtn) stopBtn.style.display = 'none';
    return;
  }

  let done = 0;
  _bulkScan.ids.forEach(id => {
    const j = state.jobs[id];
    // A job counts as done when it's no longer queued or scanning
    if (!j || (j.status !== 'queued' && j.status !== 'scanning')) done++;
  });

  const total = _bulkScan.total;

  if (scanAllBtn) {
    scanAllBtn.style.visibility = '';
    scanAllBtn.disabled = true;
    scanAllBtn.textContent = `⏳ ${done} / ${total} done`;
  }
  if (stopBtn) stopBtn.style.display = '';

  if (done >= total) {
    setBulkScan(null);
    if (stopBtn) stopBtn.style.display = 'none';
    showToast(`Bulk scan complete — ${done} jobs processed`, 'success', 5000);
    updateScanAllBtn(); // Restore normal button state
  }
}

async function stopAllScans() {
  const stopBtn = $('stopAllBtn');
  if (stopBtn) { stopBtn.disabled = true; stopBtn.textContent = 'Stopping…'; }
  try {
    await fetch('/api/jobs/stop-all', { method: 'POST' });
    setBulkScan(null);
    if (stopBtn) { stopBtn.style.display = 'none'; stopBtn.disabled = false; stopBtn.textContent = '⏹ Stop All'; }
    showToast('All scans stopped — queued jobs remain and can be restarted', 'warn', 5000);
    await fetchJobs();
  } catch (e) {
    if (stopBtn) { stopBtn.disabled = false; stopBtn.textContent = '⏹ Stop All'; }
    showToast('Failed to stop scans', 'error');
  }
}

async function scanAll() {
  const ids = filteredJobs().filter(j => (j.status === 'queued' || j.status === 'error') && j.triage !== 'closed').map(j => j.id);
  if (!ids.length) return;
  const btn = $('scanAllBtn');
  if (btn) { btn.disabled = true; btn.textContent = 'Starting…'; }

  try {
    const res = await fetch('/api/jobs/scan-batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ job_ids: ids })
    });
    const data = await res.json();
    if (!res.ok) {
      showToast(data.detail || 'Failed to start scans', 'error');
      if (btn) { btn.disabled = false; btn.textContent = '▶▶ Scan All'; }
      return;
    }
    const enqueued = data.enqueued || 0;
    // Track bulk scan progress — jobs transition queued→scanning→completed via the worker
    if (enqueued > 0) {
      // Optimistically update status so updateBulkProgress doesn't instantly consider them done
      ids.forEach(id => {
        if (state.jobs[id]) state.jobs[id].status = 'queued';
      });
      setBulkScan({ total: enqueued, ids: new Set(ids) });
    }
    showToast(`${enqueued} scan${enqueued !== 1 ? 's' : ''} queued — processing 1 by 1`, 'success');
    renderJobList();
    updateStats();
  } catch (e) {
    showToast('Failed to start scans: ' + e.message, 'error');
    if (btn) { btn.disabled = false; btn.textContent = '▶▶ Scan All'; }
  }
}

// ── Copy terminal output ───────────────────────────────────────────────────
function copyTerminal(jobId) {
  const job = state.jobs[jobId];
  if (!job) return;
  const text = (job.output_lines || []).join('\n');
  navigator.clipboard.writeText(text)
    .then(() => showToast('Output copied to clipboard', 'success', 2500))
    .catch(() => showToast('Copy failed — select text manually', 'warn'));
}

// ── Select / check ────────────────────────────────────────────────────────
async function selectJob(jobId, e) {
  if (e && e.target.type === 'checkbox') return;
  state.selectedJobId = jobId;
  renderJobList();

  // Decide whether to (re-)fetch full job data from the server:
  //   1. Never fetched before (_full not set)
  //   2. Background scan completed/errored without a stream — _full was set on
  //      scan start to protect output_lines during the run, but no stream was
  //      ever open so output_lines is still the empty array we set at launch.
  //      We must re-fetch to get the real output the server recorded.
  const job = state.jobs[jobId];
  const isFinished   = job?.status === 'completed' || job?.status === 'error';
  const hasNoOutput  = !job?.output_lines?.length;
  const needsRefetch = !job?._full || (isFinished && hasNoOutput);

  if (needsRefetch) {
    try {
      const res = await fetch(`/api/jobs/${jobId}`);
      if (res.ok) {
        const full = await res.json();
        full._full = true;
        // Merge rather than overwrite: if the stream was already running and
        // accumulated lines in memory while this fetch was in-flight, keep
        // whichever output_lines list is longer so we never lose live output.
        const prev = state.jobs[jobId];
        if ((prev?.output_lines?.length ?? 0) > (full.output_lines?.length ?? 0)) {
          full.output_lines = prev.output_lines;
        }
        state.jobs[jobId] = full;
      }
    } catch (_) { /* ignore */ }
  }
  if (state.selectedJobId === jobId) renderDetail(jobId);
}

function toggleCheck(e, jobId) {
  e.stopPropagation();
  if (e.target.checked) state.checkedIds.add(jobId);
  else state.checkedIds.delete(jobId);
  updateScanSelectedBtn();
}

function toggleSelectAll(checked) {
  const remJobs = filteredJobs().filter(j => j.source !== 'sweep' && j.source !== 'manual');
  const rtf = state.remTypeFilter;
  const filteredRem = rtf === 'auto'   ? remJobs.filter(j => j.status !== 'manual')
                    : rtf === 'manual' ? remJobs.filter(j => j.status === 'manual')
                    : remJobs;

  const manualJobs = filteredJobs().filter(j => j.source === 'manual');
  const mtf = state.manualTypeFilter;
  const filteredManual = mtf === 'auto'   ? manualJobs.filter(j => j.status !== 'manual')
                       : mtf === 'manual' ? manualJobs.filter(j => j.status === 'manual')
                       : manualJobs;

  const sweepJobs = filteredJobs().filter(j => j.source === 'sweep');
  const tf = state.sweepTypeFilter;
  const typeFiltered = tf === 'auto'         ? sweepJobs.filter(j => j.status !== 'manual')
                     : tf === 'manual'       ? sweepJobs.filter(j => j.status === 'manual')
                     : tf === 'fixed'        ? sweepJobs.filter(j => j.status === 'completed' && j.verdict === 'fixed')
                     : tf === 'not_fixed'    ? sweepJobs.filter(j => j.status === 'completed' && j.verdict === 'not_fixed')
                     : tf === 'inconclusive' ? sweepJobs.filter(j => j.status === 'completed' && j.verdict === 'inconclusive')
                     : sweepJobs;
  const q = (state.sweepSearch || '').toLowerCase();
  const filteredSweep = q
    ? typeFiltered.filter(j =>
        (j.ticket_key && j.ticket_key.toLowerCase().includes(q)) ||
        (j.ticket_summary && j.ticket_summary.toLowerCase().includes(q)) ||
        (j.vulnerability_title && j.vulnerability_title.toLowerCase().includes(q))
      )
    : typeFiltered;

  const visibleIds = [...filteredRem, ...filteredManual, ...filteredSweep]
    .filter(j => (j.status === 'queued' || j.status === 'error') && j.triage !== 'closed')
    .map(j => j.id);

  if (checked) {
    visibleIds.forEach(id => state.checkedIds.add(id));
  } else {
    visibleIds.forEach(id => state.checkedIds.delete(id));
  }
  updateScanSelectedBtn();
  renderJobList();
}

function toggleSelectAllSweep(checked, event) {
  if (event) {
    event.stopPropagation();
  }
  const sweepJobs = filteredJobs().filter(j => j.source === 'sweep');
  const tf = state.sweepTypeFilter;
  const typeFiltered = tf === 'auto'         ? sweepJobs.filter(j => j.status !== 'manual')
                     : tf === 'manual'       ? sweepJobs.filter(j => j.status === 'manual')
                     : tf === 'fixed'        ? sweepJobs.filter(j => j.status === 'completed' && j.verdict === 'fixed')
                     : tf === 'not_fixed'    ? sweepJobs.filter(j => j.status === 'completed' && j.verdict === 'not_fixed')
                     : tf === 'inconclusive' ? sweepJobs.filter(j => j.status === 'completed' && j.verdict === 'inconclusive')
                     : sweepJobs;
  const q = (state.sweepSearch || '').toLowerCase();
  const filteredSweep = q
    ? typeFiltered.filter(j =>
        (j.ticket_key && j.ticket_key.toLowerCase().includes(q)) ||
        (j.ticket_summary && j.ticket_summary.toLowerCase().includes(q)) ||
        (j.vulnerability_title && j.vulnerability_title.toLowerCase().includes(q))
      )
    : typeFiltered;

  const ids = filteredSweep.filter(j => (j.status === 'queued' || j.status === 'error') && j.triage !== 'closed').map(j => j.id);
  if (checked) {
    ids.forEach(id => state.checkedIds.add(id));
  } else {
    ids.forEach(id => state.checkedIds.delete(id));
  }
  updateScanSelectedBtn();
  renderJobList();
}

function toggleSelectAllRem(checked, event) {
  if (event) {
    event.stopPropagation();
  }
  const remJobs = filteredJobs().filter(j => j.source !== 'sweep' && j.source !== 'manual');
  const rtf = state.remTypeFilter;
  const filteredRem = rtf === 'auto'   ? remJobs.filter(j => j.status !== 'manual')
                    : rtf === 'manual' ? remJobs.filter(j => j.status === 'manual')
                    : remJobs;
  const ids = filteredRem.filter(j => (j.status === 'queued' || j.status === 'error') && j.triage !== 'closed').map(j => j.id);
  if (checked) {
    ids.forEach(id => state.checkedIds.add(id));
  } else {
    ids.forEach(id => state.checkedIds.delete(id));
  }
  updateScanSelectedBtn();
  renderJobList();
}

function toggleSelectAllManual(checked, event) {
  if (event) {
    event.stopPropagation();
  }
  const manualJobs = filteredJobs().filter(j => j.source === 'manual');
  const mtf = state.manualTypeFilter;
  const filteredManual = mtf === 'auto'   ? manualJobs.filter(j => j.status !== 'manual')
                       : mtf === 'manual' ? manualJobs.filter(j => j.status === 'manual')
                       : manualJobs;
  const ids = filteredManual.filter(j => (j.status === 'queued' || j.status === 'error') && j.triage !== 'closed').map(j => j.id);
  if (checked) {
    ids.forEach(id => state.checkedIds.add(id));
  } else {
    ids.forEach(id => state.checkedIds.delete(id));
  }
  updateScanSelectedBtn();
  renderJobList();
}

function updateScanSelectedBtn() {
  const btn = $('scanSelectedBtn');
  const count = [...state.checkedIds].filter(id => {
    const j = state.jobs[id];
    return j && (j.status === 'queued' || j.status === 'error');
  }).length;
  btn.disabled = count === 0;
  btn.textContent = count > 0 ? `▶ Scan Selected (${count})` : '▶ Scan Selected';
}

// ── Render detail ─────────────────────────────────────────────────────────
function renderDetail(jobId) {
  const job = state.jobs[jobId];
  if (!job) return;

  const panel = $('detailPanel');
  const sevClass = job.ticket_severity ? `sev-${job.ticket_severity.toLowerCase()}` : '';
  const cveHtml = (job.ticket_cves || []).map(c => `<span style="color:var(--orange);font-size:10px">${escHtml(c)}</span>`).join(' ');

  panel.innerHTML = `
    <div class="detail-view">

      <div class="detail-header">
        <div class="detail-key">${escHtml(job.ticket_key)} · ${escHtml(job.client_label)}</div>
        <div class="detail-summary">${escHtml(job.ticket_summary)}</div>
        <div class="detail-meta">
          <div class="meta-item">
            <span class="meta-label">IP</span>
            <span class="meta-value">${escHtml(job.ip) || '—'}</span>
          </div>
          <div class="meta-item">
            <span class="meta-label">Port</span>
            <span class="meta-value">${escHtml(job.port) || '—'}</span>
          </div>
          <div class="meta-item">
            <span class="meta-label">CVSS</span>
            <span class="meta-value ${sevClass}">${escHtml(job.ticket_cvss) || '—'}</span>
          </div>
          <div class="meta-item">
            <span class="meta-label">Severity</span>
            <span class="meta-value ${sevClass}">${escHtml(job.ticket_severity) || '—'}</span>
          </div>
          <div class="meta-item">
            <span class="meta-label">TestType</span>
            <span class="meta-value" style="color:${job.ticket_testtype && ['SCN','IPT'].includes(job.ticket_testtype) ? 'var(--cyan)' : 'var(--yellow,#e6a817)'};font-size:10px">
              ${escHtml(job.ticket_testtype) || '—'}
              ${job.status === 'manual' ? ' · 🖐 Manual' : ' · ⚡ Auto'}
            </span>
          </div>
          <div class="meta-item">
            <span class="meta-label">Rule</span>
            <span class="meta-value" style="color:var(--cyan);font-size:10px">${escHtml(job.rule_name || 'No matching rule')}</span>
          </div>
        </div>
        ${cveHtml ? `<div style="margin-top:6px;display:flex;gap:6px;flex-wrap:wrap">${cveHtml}</div>` : ''}
        ${job.nmap_command ? `
          <div style="margin-top:8px">
            <span style="font-size:10px;color:var(--text-dim)">COMMAND: </span>
            <code style="font-size:10px;color:var(--purple)">${escHtml(job.nmap_command)}</code>
          </div>` : ''}
      </div>

      ${job.status === 'manual' ? `
      <div class="terminal-section">
        <div class="terminal-header">
          <span class="terminal-title">🖐 MANUAL REVIEW</span>
          <span style="font-size:11px;color:var(--yellow,#e6a817)">No automated scan rule — review manually and set verdict below</span>
        </div>
        <div class="terminal" style="padding:14px;white-space:pre-wrap;font-family:inherit;font-size:12px;line-height:1.6;color:var(--text)">
${job.ticket_description
  ? escHtml(job.ticket_description).replace(/\n/g, '<br>')
  : '<span style="color:var(--text-dim)">No description available — open the Jira ticket for full details.</span>'}
        </div>
      </div>

      <div class="action-bar">
        ${renderVerdictBadge(job)}
        <span class="verdict-reason">${escHtml(job.verdict_reason || '')}</span>
        <div style="display:flex;gap:8px;margin-left:auto;flex-shrink:0">
          ${!job.jira_updated ? renderTransitionBtns(job) : ''}
          ${job.jira_updated ? `<span style="color:var(--green);font-size:12px">✔ Jira Updated</span>` : ''}
        </div>
      </div>
      ` : `
      <div class="terminal-section">
        <div class="terminal-header">
          <span class="terminal-title">SCAN OUTPUT</span>
          <div style="display:flex;align-items:center;gap:10px">
            <span id="scanStatusLabel" style="font-size:11px;color:var(--text-dim)">${statusLabel(job)}</span>
            <button class="btn btn-sm btn-secondary" onclick="copyTerminal('${jobId}')" title="Copy output to clipboard">📋 Copy</button>
          </div>
        </div>
        <div class="terminal" id="terminal-${jobId}">${renderTerminalLines(job.output_lines || [])}</div>
      </div>

      <div class="action-bar">
        ${renderVerdictBadge(job)}
        <span class="verdict-reason">${escHtml(job.verdict_reason || '')}</span>
        <div style="display:flex;gap:8px;margin-left:auto;flex-shrink:0">
          ${job.status === 'queued' ? `
            <button class="btn btn-primary" onclick="triggerScan('${jobId}')">▶ Scan</button>
          ` : ''}
          ${job.status === 'scanning' ? `
            <button class="btn btn-red btn-sm" onclick="stopScan('${jobId}')">⏹ Stop</button>
          ` : ''}
          ${job.status === 'completed' || job.status === 'error' ? `
            <button class="btn btn-secondary btn-sm" onclick="resetJob('${jobId}')">↺ Re-scan</button>
          ` : ''}
          ${(job.status === 'completed' || job.status === 'error') && !job.jira_updated ? renderTransitionBtns(job) : ''}
          ${job.jira_updated ? `<span style="color:var(--green);font-size:12px">✔ Jira Updated</span>` : ''}
        </div>
      </div>
      `}

    </div>`;

  // Ensure only this job's stream is open — close all others
  closeOtherStreams(jobId);
  if (job.status === 'scanning' && !state.activeStreams[jobId]) {
    openStream(jobId);
  }
  scrollTerminal(jobId);
}

function renderTerminalLines(lines) {
  return lines.map(l => `<div class="${lineClass(l)}">${escHtml(l)}</div>`).join('');
}

function lineClass(line) {
  if (line.startsWith('[INFO]'))    return 'line-info';
  if (line.startsWith('[SSH]'))     return 'line-ssh';
  if (line.startsWith('[NMAP]'))    return 'line-nmap';
  if (line.startsWith('[PARSE]'))   return 'line-parse';
  if (line.startsWith('[VERDICT]')) return 'line-verdict';
  if (line.startsWith('[RESULT]'))  return 'line-verdict';
  if (line.startsWith('[ERROR]'))   return 'line-error';
  if (line.startsWith('─'))         return 'line-sep';
  return '';
}

function renderVerdictBadge(job) {
  const v = job.verdict;
  if (!v) return `<span class="verdict-badge verdict-none">${job.status === 'scanning' ? '🔍 Scanning…' : '—'}</span>`;
  const labels = { fixed: '✅ FIXED', not_fixed: '❌ NOT FIXED', inconclusive: '⚠️ INCONCLUSIVE' };
  return `<span class="verdict-badge verdict-${v}">${labels[v] || v.toUpperCase()}</span>`;
}

function statusLabel(job) {
  const map = {
    queued:    'Waiting to scan',
    scanning:  '🔍 Scanning…',
    completed: 'Scan complete',
    error:     'Scan error',
    manual:    '🖐 Manual review',
  };
  return map[job.status] || job.status;
}

// ── Live stream ───────────────────────────────────────────────────────────
function openStream(jobId) {
  if (state.activeStreams[jobId]) state.activeStreams[jobId].close();

  const es = new EventSource(`/api/jobs/${jobId}/stream`);
  state.activeStreams[jobId] = es;

  es.onmessage = (e) => {
    let data;
    try { data = JSON.parse(e.data); } catch { return; }
    if (data.line !== undefined) {
      appendTerminalLine(jobId, data.line);
    }
    if (data.done) {
      es.close();
      delete state.activeStreams[jobId];
      // Refresh this job's full state from the server.
      // Merge rather than overwrite: keep whichever output_lines is longer
      // (in-memory stream lines vs server-recorded lines) so we never drop
      // a line that arrived via the stream but hasn't persisted yet.
      fetch(`/api/jobs/${jobId}`)
        .then(r => r.ok ? r.json() : null)
        .then(j => {
          if (!j) return;
          j._full = true;
          const prev = state.jobs[jobId];
          if ((prev?.output_lines?.length ?? 0) > (j.output_lines?.length ?? 0)) {
            j.output_lines = prev.output_lines;
          }
          state.jobs[jobId] = j;
          if (state.selectedJobId === jobId) renderDetail(jobId);
          renderJobList();
          updateStats();
        })
        .catch(() => {});
    }
  };

  es.onerror = () => {
    es.close();
    delete state.activeStreams[jobId];
  };
}

const TERMINAL_MAX_LINES = 5000;

function appendTerminalLine(jobId, line) {
  // Update in-memory job, capping retained lines so a long/verbose scan can't
  // grow the array (and its serialized copies) without bound for the session.
  if (state.jobs[jobId]) {
    const lines = state.jobs[jobId].output_lines || (state.jobs[jobId].output_lines = []);
    lines.push(line);
    if (lines.length > TERMINAL_MAX_LINES) {
      lines.splice(0, lines.length - TERMINAL_MAX_LINES);
    }
  }
  // Append to live terminal if visible, capping rendered nodes to match.
  const term = document.getElementById(`terminal-${jobId}`);
  if (term) {
    const div = document.createElement('div');
    div.className = lineClass(line);
    div.textContent = line;
    term.appendChild(div);
    while (term.childElementCount > TERMINAL_MAX_LINES) {
      term.removeChild(term.firstChild);
    }
    term.scrollTop = term.scrollHeight;
  }
}

function scrollTerminal(jobId) {
  const term = document.getElementById(`terminal-${jobId}`);
  if (term) term.scrollTop = term.scrollHeight;
}

// Close every active SSE stream except the one we're about to show
function closeOtherStreams(keepJobId) {
  Object.keys(state.activeStreams).forEach(id => {
    if (id !== keepJobId) {
      state.activeStreams[id].close();
      delete state.activeStreams[id];
    }
  });
}

// ── Actions ───────────────────────────────────────────────────────────────
async function triggerScan(jobId) {
  try {
    const res = await fetch(`/api/jobs/${jobId}/scan`, { method: 'POST' });
    if (!res.ok) {
      const err = await res.json();
      showToast(`Scan error: ${err.detail}`, 'error');
      return;
    }
    // Mark _full=true so fetchJobs polls never overwrite output_lines with the
    // slim list response (which has no output_lines field) — previously this
    // caused the terminal to go blank mid-scan.
    state.jobs[jobId]._full        = true;
    state.jobs[jobId].status       = 'scanning';
    state.jobs[jobId].output_lines = [];
    renderJobList();
    renderDetail(jobId);  // opens stream via closeOtherStreams + openStream
  } catch (e) {
    showToast(`Failed to start scan: ${e.message}`, 'error');
  }
}

async function scanSelected() {
  const ids = [...state.checkedIds].filter(id => {
    const status = state.jobs[id]?.status;
    return status === 'queued' || status === 'error';
  });
  if (!ids.length) return;

  try {
    const res = await fetch('/api/jobs/scan-batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ job_ids: ids })
    });
    const data = await res.json();
    if (!res.ok) {
      showToast(data.detail || 'Failed to start scans', 'error');
      return;
    }
    const enqueued = data.enqueued || 0;
    if (enqueued > 0) {
      // Optimistically update status so updateBulkProgress doesn't instantly consider them done
      ids.forEach(id => {
        if (state.jobs[id]) state.jobs[id].status = 'queued';
        state.checkedIds.delete(id);
      });
      setBulkScan({ total: enqueued, ids: new Set(ids) });
    }
    showToast(`${enqueued} scan${enqueued !== 1 ? 's' : ''} queued`, 'success');
    renderJobList();
    updateStats();
  } catch (e) {
    showToast('Failed to start scans: ' + e.message, 'error');
  }
  // Only open stream for the selected job
  const _sel = state.selectedJobId && state.jobs[state.selectedJobId];
  if (_sel && _sel.status === 'scanning' && !state.activeStreams[_sel.id]) {
    openStream(_sel.id);
    renderDetail(state.selectedJobId);
  }
  updateScanSelectedBtn();
}

async function stopScan(jobId) {
  try {
    await fetch(`/api/jobs/${jobId}/stop`, { method: 'POST' });
  } catch (e) { /* ignore — scan thread handles cleanup */ }
}

async function resetJob(jobId) {
  try {
    const r = await fetch(`/api/jobs/${jobId}/reset`, { method: 'POST' });
    if (!r.ok) { showToast('Reset failed', 'error'); return; }
    const res = await fetch(`/api/jobs/${jobId}`);
    if (!res.ok) { showToast('Could not reload job after reset', 'warn'); return; }
    const full = await res.json();
    full._full = true;
    state.jobs[jobId] = full;
    renderJobList();
    if (state.selectedJobId === jobId) renderDetail(jobId);
  } catch (e) {
    showToast(`Reset failed: ${e.message}`, 'error');
  }
}

async function removeJob(jobId, e) {
  e && e.stopPropagation();
  const job = state.jobs[jobId];
  if (!job) return;
  if (!confirm(`Remove ${job.ticket_key} from queue?\nIt will re-appear on the next Jira poll if still Remediated.`)) return;
  await fetch(`/api/jobs/${jobId}`, { method: 'DELETE' });
  // Close any active SSE stream for this job before removing it from state
  if (state.activeStreams[jobId]) {
    state.activeStreams[jobId].close();
    delete state.activeStreams[jobId];
  }
  delete state.jobs[jobId];
  state.checkedIds.delete(jobId);
  if (state.selectedJobId === jobId) {
    state.selectedJobId = null;
    $('detailPanel').innerHTML = `<div class="empty-state"><div class="empty-icon">⚡</div><div>Select a ticket from the queue to view details</div></div>`;
  }
  renderJobList();
  updateStats();
}

async function forcePoll() {
  const btn = $('pollNowBtn');
  btn.disabled = true;
  btn.textContent = '↻ Polling…';
  // Fire and forget — never waits, never blocks.
  fetch('/api/poll', { method: 'POST' }).catch(() => {});
  // Re-enable after 3s and refresh the UI. A second refresh at 8s catches
  // slower Jira responses without blocking the button.
  setTimeout(() => {
    btn.disabled = false;
    btn.textContent = '↻ Poll Now';
    fetchJobs();
    fetchLogs();
  }, 3000);
  setTimeout(() => {
    fetchJobs();
    fetchLogs();
  }, 8000);
}

// ── Transition modal ──────────────────────────────────────────────────────
let _pendingTransition = null;
let _transitionScreenshot = null;

function _clearTransitionScreenshot() {
  if (_transitionScreenshot?.previewUrl) URL.revokeObjectURL(_transitionScreenshot.previewUrl);
  _transitionScreenshot = null;
  const preview = $('modalScreenshotPreview');
  if (preview) {
    preview.innerHTML = '';
    preview.style.display = 'none';
  }
}

function _setTransitionScreenshot(file) {
  if (!file || !file.type.startsWith('image/')) return;
  _clearTransitionScreenshot();
  const previewUrl = URL.createObjectURL(file);
  const name = file.name || `screenshot-${Date.now()}.png`;
  _transitionScreenshot = { blob: file, previewUrl, name };
  const preview = $('modalScreenshotPreview');
  if (!preview) return;
  preview.innerHTML = `
    <div class="screenshot-preview-bar">
      <span>📎 ${escHtml(name)}</span>
      <button type="button" class="btn btn-sm btn-secondary" onclick="removeTransitionScreenshot()">Remove</button>
    </div>
    <img src="${previewUrl}" alt="Pasted screenshot preview">`;
  preview.style.display = 'block';
}

function removeTransitionScreenshot() {
  _clearTransitionScreenshot();
}

function _buildTransitionFormData(fields) {
  const fd = new FormData();
  for (const [key, value] of Object.entries(fields)) {
    if (value != null && value !== '') fd.append(key, value);
  }
  return fd;
}

function _handleTransitionPaste(e) {
  const items = e.clipboardData?.items;
  if (!items) return;
  for (const item of items) {
    if (item.type.startsWith('image/')) {
      e.preventDefault();
      const file = item.getAsFile();
      if (file) _setTransitionScreenshot(file);
      return;
    }
  }
}

// ── Fast-track helpers ─────────────────────────────────────────────────────

// Intermediate steps only (not including the phase-1 target "Remediated").
// Phase 1 always advances to Remediated; phase 2 goes Fixed/Not Fixed.
const _FAST_TRACK_CHAINS = {
  'reported':    ['In Progress'],          // → In Progress → Remediated (phase 1)
  'in progress': [],                       // → Remediated directly
  'not fixed':   ['Refix', 'Fix Issue'],   // Refix unlocks; Fix Issue reaches Remediated
  'remediated':  [],                       // already there — phase 2: Fixed / Not Fixed
};

/** Full display chain for phase 1 (always to Remediated). */
function fastTrackChainToRemediated(ticketStatus) {
  const s = (ticketStatus || '').toLowerCase().trim();
  const intermediates = _FAST_TRACK_CHAINS[s];
  if (intermediates === undefined) return null;
  return [...intermediates, 'Remediated'];
}

function needsFastTrack(job) {
  const s = (job.ticket_status || '').toLowerCase().trim();
  return s in _FAST_TRACK_CHAINS && s !== 'remediated';
}

/** Render transition buttons.
 *  - Pre-Remediated ticket → single "⚡ → Remediated" button (phase 1).
 *  - Remediated ticket     → ✅ Fixed / ❌ Not Fixed (phase 2, direct). */
function renderTransitionBtns(job) {
  const jid = job.id;
  if (needsFastTrack(job)) {
    // For sweeped/pre-remediated tickets, do not show the option to move to Remediated if the scan has run and the verdict is not fixed.
    if ((job.status === 'completed' || job.status === 'error') && job.verdict !== 'fixed') {
      return '';
    }
    const chain = fastTrackChainToRemediated(job.ticket_status) || [];
    const tip   = chain.length > 1
      ? `Via: ${chain.slice(0, -1).join(' → ')} → Remediated`
      : 'Move to Remediated — click again to mark Fixed / Not Fixed';
    // The "toStatus" we pass is the EVENTUAL target the user clicked;
    // the backend will stop at Remediated for phase 1.
    return `
      <button class="btn btn-sweep" onclick="openFastTrack('${jid}','Fixed')"
              title="${escHtml(tip)}">⚡ → Remediated</button>`;
  }
  return `
    <button class="btn btn-green" onclick="openTransition('${jid}','Fixed')">✅ Fixed</button>
    <button class="btn btn-red"   onclick="openTransition('${jid}','Not Fixed')">❌ Not Fixed</button>`;
}

function openFastTrack(jobId, target) {
  _clearTransitionScreenshot();
  const job  = state.jobs[jobId];
  const s    = (job.ticket_status || '').toLowerCase().trim();
  const at_remediated = s === 'remediated';

  // What will actually happen this click?
  const chain = at_remediated
    ? ['Remediated', target]
    : (fastTrackChainToRemediated(job.ticket_status) || ['Remediated']);

  _pendingTransition = { jobId, toStatus: target, isFastTrack: true };
  $('modalTitle').textContent    = at_remediated
    ? `⚡ Fast-track → ${target}`
    : `⚡ Advance → Remediated`;
  $('modalSubtitle').textContent =
    `${job.ticket_key} (${job.ticket_status || '?'})  →  ${chain.join(' → ')}`;
  $('modalComment').value = buildAutoComment(job, at_remediated ? target : 'Remediated');
  $('transitionModal').style.display = 'flex';
}

function openTransition(jobId, toStatus) {
  _clearTransitionScreenshot();
  _pendingTransition = { jobId, toStatus };
  const job = state.jobs[jobId];
  $('modalTitle').textContent = `Confirm: Mark as ${toStatus}`;
  $('modalSubtitle').textContent = `Ticket: ${job.ticket_key} — ${truncate(job.ticket_summary, 60)}`;
  $('modalComment').value = buildAutoComment(job, toStatus);
  $('transitionModal').style.display = 'flex';
}

function buildAutoComment(job, toStatus) {
  const ts = new Date().toISOString().slice(0, 16).replace('T', ' ');
  const verdict = job.verdict_reason ? `\nVerdict: ${job.verdict_reason}` : '';
  return `Retest performed on ${ts} UTC\nStatus: ${toStatus}${verdict}\nNmap rule: ${job.rule_name || 'manual review'}\nTarget: ${job.ip || 'N/A'}:${job.port || 'N/A'}`;
}

async function confirmTransition() {
  if (!_pendingTransition) return;
  const { jobId, toStatus, isFastTrack } = _pendingTransition;
  const comment    = $('modalComment').value.trim();
  const ticketKey  = state.jobs[jobId]?.ticket_key;
  const screenshot = _transitionScreenshot;
  $('transitionModal').style.display = 'none';
  _pendingTransition = null;
  _clearTransitionScreenshot();

  if (isFastTrack) {
    try {
      const fd = _buildTransitionFormData({ target: toStatus, comment });
      if (screenshot) fd.append('screenshot', screenshot.blob, screenshot.name);
      const res = await fetch(`/api/jobs/${jobId}/fast-track`, {
        method: 'POST',
        body: fd,
      });
      if (!res.ok) {
        const err = await res.json();
        const detail    = typeof err.detail === 'object' ? err.detail.detail    : (err.detail || 'Unknown error');
        const completed = typeof err.detail === 'object' ? err.detail.completed : [];
        const doneStr   = completed.length ? ` (completed: ${completed.join(' → ')})` : '';
        showToast(`Fast-track failed: ${detail}${doneStr}`, 'error', 8000);
        return;
      }
      const data = await res.json();
      if (data.partial) {
        // Phase 1 complete — ticket now at Remediated, stays on board
        if (state.jobs[jobId]) {
          state.jobs[jobId].ticket_status = data.current_status;
        }
        showToast(
          `⚡ ${ticketKey}: ${data.chain.join(' → ')} — now in ${data.current_status}. Click again to mark Fixed / Not Fixed.`,
          'success', 7000
        );
        renderJobList();
      } else {
        // Phase 2 complete — remove job
        _removeJobLocally(jobId);
        showToast(`⚡ ${ticketKey}: ${data.chain.join(' → ')}`, 'success', 5000);
        renderJobList();
        updateStats();
      }
    } catch (e) {
      showToast(e.message, 'error');
    }
    return;
  }

  // ── Standard single-step transition ──────────────────────────────────────
  try {
    const fd = _buildTransitionFormData({ job_id: jobId, to_status: toStatus, comment });
    if (screenshot) fd.append('screenshot', screenshot.blob, screenshot.name);
    const res = await fetch('/api/transition', {
      method: 'POST',
      body: fd,
    });
    if (!res.ok) {
      const err = await res.json();
      showToast(`Transition failed: ${err.detail}`, 'error');
      return;
    }
    _removeJobLocally(jobId);
    showToast(`${ticketKey} → ${toStatus}`, 'success');
    renderJobList();
    updateStats();
  } catch (e) {
    showToast(e.message, 'error');
  }
}

function _removeJobLocally(jobId) {
  delete state.jobs[jobId];
  state.checkedIds.delete(jobId);
  if (state.selectedJobId === jobId) {
    state.selectedJobId = null;
    $('detailPanel').innerHTML = `<div class="empty-state"><div class="empty-icon">⚡</div><div>Select a ticket from the queue to view details</div></div>`;
  }
}

// ── Bulk transition modal ─────────────────────────────────────────────────

// Holds the current status groups so per-group buttons can reference them by index
let _transitionGroups = [];

async function openTransitionModal() {
  $('transitionPreviewBody').innerHTML = '<span style="color:var(--text-dim)">⏳ Loading…</span>';
  $('transitionTicketList').style.display = 'none';
  $('transitionTicketList').innerHTML = '';
  $('transitionConfirmBtn').disabled = true;
  $('bulkTransitionModal').style.display = 'flex';
  await _loadTransitionPreview();
}

async function _loadTransitionPreview() {
  $('transitionPreviewBody').innerHTML = '<span style="color:var(--text-dim)">⏳ Loading…</span>';
  $('transitionTicketList').style.display = 'none';
  $('transitionConfirmBtn').disabled = true;
  _transitionGroups = [];

  try {
    const res  = await fetch('/api/jobs/transition-preview');
    const data = await res.json();
    const nFixed    = data.to_fixed.length;
    const nNotFixed = data.to_not_fixed.length;
    const total     = nFixed + nNotFixed;

    if (total === 0) {
      $('transitionPreviewBody').innerHTML =
        '<span style="color:var(--text-dim)">No eligible tickets to transition.</span>';
      return;
    }

    const retestStatus = (await fetch('/api/config').then(r => r.json())).retest_status || 'Remediated';

    // Merge all eligible tickets; at Remediated, group by verdict target too
    const allTickets = [
      ...data.to_fixed.map(t    => ({...t, verdictTarget: 'Fixed'})),
      ...data.to_not_fixed.map(t => ({...t, verdictTarget: 'Not Fixed'})),
    ];
    const groupMap = {};
    allTickets.forEach(t => {
      const s = t.ticket_status || 'Unknown';
      const isRemediated = s.toLowerCase() === retestStatus.toLowerCase();
      const groupKey = isRemediated ? `${s}::${t.verdictTarget}` : s;
      if (!groupMap[groupKey]) {
        groupMap[groupKey] = {
          status: s,
          verdictTarget: isRemediated ? t.verdictTarget : 'Remediated',
          jobs: [],
        };
      }
      groupMap[groupKey].jobs.push(t);
    });

    // Sort: Remediated last (phase 2); pre-Remediated states first (phase 1)
    const _STATUS_ORDER = ['Reported', 'In Progress', 'Not Fixed', 'Refix', 'Remediated'];
    const _TARGET_ORDER = { 'Remediated': 0, 'Fixed': 1, 'Not Fixed': 2 };
    _transitionGroups = Object.values(groupMap).sort((a, b) => {
      const ai = _STATUS_ORDER.findIndex(s => s.toLowerCase() === a.status.toLowerCase());
      const bi = _STATUS_ORDER.findIndex(s => s.toLowerCase() === b.status.toLowerCase());
      const statusCmp = (ai === -1 ? 50 : ai) - (bi === -1 ? 50 : bi);
      if (statusCmp !== 0) return statusCmp;
      return (_TARGET_ORDER[a.verdictTarget] ?? 9) - (_TARGET_ORDER[b.verdictTarget] ?? 9);
    });

    const groupsHtml = _transitionGroups.map((g, idx) => {
      const isRemediated = g.status.toLowerCase() === retestStatus.toLowerCase();
      const n = g.jobs.length;
      const keys = g.jobs.map(j => j.ticket_key).join(', ');
      const target = g.verdictTarget;
      const btnLabel = isRemediated
        ? `${target === 'Fixed' ? '✅' : '❌'} Transition ${n} → ${target}`
        : `⚡ Advance ${n} → Remediated`;
      const btnClass = isRemediated
        ? (target === 'Fixed' ? 'btn-green' : 'btn-red')
        : 'btn-sweep';
      return `
        <div style="border:1px solid var(--border);border-radius:4px;padding:8px 10px;background:var(--bg3);display:flex;flex-direction:column;gap:5px">
          <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:10px">
            <div style="flex:1;min-width:0">
              <div style="font-size:11px;font-weight:600;color:var(--text);margin-bottom:3px">
                ${escHtml(g.status)}${isRemediated ? ` → ${escHtml(target)}` : ''}
                <span style="font-weight:400;color:var(--text-dim)">(${n})</span>
              </div>
              <div style="font-size:11px;color:var(--cyan);user-select:all;cursor:text;word-break:break-all">${escHtml(keys)}</div>
            </div>
            <button class="btn btn-sm ${btnClass}" style="white-space:nowrap;flex-shrink:0"
                    id="transGroupBtn${idx}"
                    onclick="_advanceTransitionGroup(${idx})">${btnLabel}</button>
          </div>
        </div>`;
    }).join('');

    $('transitionPreviewBody').innerHTML = `
      <div style="display:flex;flex-direction:column;gap:6px">
        ${groupsHtml}
        <div style="font-size:11px;color:var(--text-dim);margin-top:2px">
          Tickets marked Inconclusive or Error are excluded.
        </div>
      </div>`;

    // Build ticket detail list
    $('transitionTicketList').innerHTML = allTickets.map(t => {
      const icon = t.verdictTarget === 'Fixed' ? '✅' : '❌';
      return `
        <div style="display:flex;align-items:center;gap:8px;padding:6px 10px;border-bottom:1px solid var(--border);font-size:11px">
          <span>${icon}</span>
          <span style="font-weight:600;white-space:nowrap">${escHtml(t.ticket_key)}</span>
          <span style="flex:1;color:var(--text-dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(truncate(t.ticket_summary, 55))}</span>
          <span style="color:var(--text-dim);white-space:nowrap;font-size:10px">${escHtml(t.ticket_status || '')}</span>
          <span style="color:var(--text-dim);white-space:nowrap">${escHtml(t.client_label)}</span>
        </div>`;
    }).join('');
    $('transitionTicketList').style.display = '';

    // Bottom button: only for Remediated tickets — the per-group ⚡ buttons handle
    // phase-1 (advancing to Remediated first).
    const remCount = _transitionGroups
      .filter(g => g.status.toLowerCase() === retestStatus.toLowerCase())
      .reduce((sum, g) => sum + g.jobs.length, 0);
    const hasPreRemediated = _transitionGroups.some(g =>
      g.status.toLowerCase() !== retestStatus.toLowerCase()
    );
    if (remCount > 0) {
      $('transitionConfirmBtn').disabled = false;
      $('transitionConfirmBtn').textContent =
        hasPreRemediated
          ? `Transition ${remCount} Remediated Ticket${remCount !== 1 ? 's' : ''}`
          : `Transition ${total} Ticket${total !== 1 ? 's' : ''}`;
    } else {
      $('transitionConfirmBtn').disabled = true;
      $('transitionConfirmBtn').textContent = 'Advance to Remediated first ↑';
    }
  } catch (e) {
    $('transitionPreviewBody').innerHTML = `<span style="color:var(--red)">⚠️ ${escHtml(e.message)}</span>`;
  }
}

async function _advanceTransitionGroup(groupIdx) {
  const group = _transitionGroups[groupIdx];
  if (!group) return;

  const target = group.verdictTarget || 'Fixed';

  // Disable all group buttons while the request is in flight
  _transitionGroups.forEach((_, i) => {
    const btn = $(`transGroupBtn${i}`);
    if (btn) btn.disabled = true;
  });
  $('transitionConfirmBtn').disabled = true;

  const jobIds = group.jobs.map(j => j.job_id);
  try {
    const res = await fetch('/api/jobs/bulk-fast-track', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ job_ids: jobIds, target }),
    });
    const data = await res.json();
    const ok   = data.succeeded.length;
    const fail = data.failed.length;

    // Sync local state immediately so the job list and stats reflect reality
    data.succeeded.forEach(s => {
      if (s.partial) {
        if (state.jobs[s.job_id]) state.jobs[s.job_id].ticket_status = s.current_status;
      } else {
        delete state.jobs[s.job_id];
        state.checkedIds.delete(s.job_id);
        if (state.selectedJobId === s.job_id) state.selectedJobId = null;
      }
    });

    const isPhase2 = target !== 'Remediated' &&
      data.succeeded.some(s => !s.partial);

    if (ok > 0) {
      const icon = target === 'Not Fixed' ? '❌' : (target === 'Fixed' ? '✅' : '⚡');
      const label = isPhase2
        ? `${icon} ${ok} ticket${ok !== 1 ? 's' : ''} → ${target}`
        : `⚡ ${ok} ticket${ok !== 1 ? 's' : ''} → Remediated`;
      showToast(label, 'success', 5000);
    }
    if (fail > 0) {
      showToast(`${fail} failed: ${data.failed[0]?.error || 'unknown'}`, 'warn', 8000);
    }

    renderJobList();
    updateStats();
    // Refresh the modal groups to reflect the new ticket_status values
    await _loadTransitionPreview();
  } catch (e) {
    showToast(`Failed: ${e.message}`, 'error');
    await _loadTransitionPreview();
  }
}

function closeTransitionModal() {
  $('bulkTransitionModal').style.display = 'none';
}

async function runBulkTransition() {
  const btn = $('transitionConfirmBtn');
  btn.disabled = true;
  btn.textContent = 'Transitioning…';
  try {
    const res  = await fetch('/api/jobs/transition-bulk', { method: 'POST' });
    const data = await res.json();
    closeTransitionModal();
    await fetchJobs();
    const ok   = data.succeeded.length;
    const fail = data.failed.length;
    if (fail === 0) {
      showToast(`${ok} ticket${ok!==1?'s':''} transitioned successfully`, 'success', 5000);
    } else {
      const firstErr = data.failed[0]?.error || 'unknown error';
      showToast(`${ok} transitioned · ${fail} failed: ${firstErr}`, 'warn', 9000);
    }
  } catch (e) {
    showToast(e.message, 'error');
    btn.disabled = false;
  }
}

// ── SSH Sessions ──────────────────────────────────────────────────────────
let _sshExpanded = true;

function toggleSshPanel() {
  _sshExpanded = !_sshExpanded;
  $('sshPanelBody').style.display = _sshExpanded ? '' : 'none';
  $('sshChevron').textContent = _sshExpanded ? '▼' : '▶';
}

async function fetchSshStatus() {
  try {
    const res = await fetch('/api/ssh/status');
    if (!res.ok) return;
    const status = await res.json();
    renderSshPanel(status);
  } catch (e) { /* ignore */ }
}

function renderSshPanel(status) {
  const body = $('sshPanelBody');
  if (!body) return;

  const rows = Object.entries(status).map(([label, st]) => {
    const dotClass = st.startsWith('connected') ? 'connected'
                   : st === 'connecting'        ? 'connecting'
                   : st.startsWith('error')     ? 'error'
                   :                              'disconnected';
    const isConnected = dotClass === 'connected';
    const isConnecting = dotClass === 'connecting';
    const detail = st.startsWith('connected') ? st.replace('connected', '').trim().replace(/[()]/g,'')
                 : st.startsWith('error')     ? st.replace('error: ','')
                 : '';

    return `
      <div class="ssh-row">
        <div class="ssh-dot ${dotClass}"></div>
        <span class="ssh-label">${escHtml(label)}</span>
        ${detail ? `<span class="ssh-detail" title="${escHtml(st)}">${escHtml(detail)}</span>` : ''}
        ${isConnecting ? `<button class="btn btn-sm btn-secondary" disabled>…</button>` : ''}
        ${!isConnecting && isConnected
          ? `<button class="btn btn-sm btn-red" onclick="sshDisconnect('${label}')">Disconnect</button>`
          : ''}
        ${!isConnecting && !isConnected
          ? `<button class="btn btn-sm btn-secondary" onclick="sshConnect('${label}')">Connect</button>`
          : ''}
        <button class="btn btn-sm btn-sweep" onclick="openSweep('${label}')" title="Sweep open tickets for this client">⟳ Sweep</button>
      </div>`;
  }).join('');

  body.innerHTML = rows || '<div style="padding:8px 12px;font-size:11px;color:var(--text-dim)">No clients configured</div>';
}

const _sshConnectPolls = {};

async function sshConnect(label) {
  try {
    // Optimistically show connecting state
    const status = await (await fetch('/api/ssh/status')).json();
    status[label] = 'connecting';
    renderSshPanel(status);

    await fetch(`/api/ssh/${label}/connect`, { method: 'POST' });
  } catch (e) {
    console.warn('SSH connect failed to start:', e);
    showToast('Could not reach the server to start the connection.', 'error');
    return;
  }

  // Clear any existing poll for this label so a double-click doesn't leave two
  // intervals running forever.
  if (_sshConnectPolls[label]) clearInterval(_sshConnectPolls[label]);

  let tries = 0;
  _sshConnectPolls[label] = setInterval(async () => {
    tries++;
    try {
      const s = await (await fetch('/api/ssh/status')).json();
      renderSshPanel(s);
      if (s[label] !== 'connecting' || tries > 30) {
        clearInterval(_sshConnectPolls[label]);
        delete _sshConnectPolls[label];
        fetchLogs();
      }
    } catch (e) {
      // Network blip while polling — stop the timer instead of spinning on errors.
      clearInterval(_sshConnectPolls[label]);
      delete _sshConnectPolls[label];
    }
  }, 1000);
}

async function sshDisconnect(label) {
  await fetch(`/api/ssh/${label}/disconnect`, { method: 'POST' });
  fetchSshStatus();
  fetchLogs();
}

// ── Logs toggle ───────────────────────────────────────────────────────────
$('logsToggle').addEventListener('click', () => {
  const bar = $('logsBar');
  const chevron = $('logsChevron');
  const isExpanded = bar.classList.toggle('expanded');
  chevron.textContent = isExpanded ? '▼' : '▲';
  if (isExpanded) fetchLogs();
});

// ── Filters ───────────────────────────────────────────────────────────────
$('clientFilter').addEventListener('change', e => {
  state.clientFilter     = e.target.value;
  state.remTypeFilter    = 'all';
  state.sweepTypeFilter  = 'all';
  state.sweepRenderLimit = 100;
  renderJobList();
  // Auto-poll Jira whenever the opco filter changes so results are always fresh
  fetch('/api/poll', { method: 'POST' }).catch(() => {});
});
$('statusFilter').addEventListener('change', e => {
  state.statusFilter     = e.target.value;
  state.remTypeFilter    = 'all';
  state.sweepTypeFilter  = 'all';
  state.sweepRenderLimit = 100;
  renderJobList();
});
$('triageFilter').addEventListener('change', e => {
  state.triageFilter     = e.target.value;
  state.remTypeFilter    = 'all';
  state.sweepTypeFilter  = 'all';
  state.sweepRenderLimit = 100;
  renderJobList();
});

// ── Scan selected button ──────────────────────────────────────────────────
$('scanSelectedBtn').addEventListener('click', scanSelected);

// ── Modal buttons ─────────────────────────────────────────────────────────
function _closeTransitionModal() {
  $('transitionModal').style.display = 'none';
  _pendingTransition = null;
  _clearTransitionScreenshot();
}
$('modalCancel').addEventListener('click', _closeTransitionModal);
$('modalConfirm').addEventListener('click', confirmTransition);
$('transitionModal').addEventListener('click', e => { if (e.target === $('transitionModal')) _closeTransitionModal(); });
$('transitionModal').addEventListener('paste', _handleTransitionPaste);
$('modalComment').addEventListener('paste', _handleTransitionPaste);

// ── Utils ─────────────────────────────────────────────────────────────────
function escHtml(s) {
  // Only treat null/undefined as empty — a legitimate 0 (port, count) must render.
  if (s === null || s === undefined) return '';
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

/**
 * Render one segmented-control filter pill for the queue toolbars.
 * @param {object} o - { label, emoji, count, active, onclick, flavor }
 *   flavor: '' | 'fixed' | 'notfixed' | 'incl' (adds a verdict color when active)
 */
function _qpill(o) {
  const flavorClass = o.flavor ? `qf-${o.flavor}` : '';
  const emoji = o.emoji ? `<span class="qf-emoji">${o.emoji}</span>` : '';
  return `<button type="button" class="qfilter-pill ${o.active ? 'active' : ''} ${flavorClass}" onclick="${o.onclick}">`
    + `${emoji}<span>${escHtml(o.label)}</span>`
    + `<span class="qf-count">${o.count}</span></button>`;
}
function truncate(s, n) {
  if (!s) return '';
  return s.length > n ? s.slice(0, n) + '…' : s;
}

// ── Add Ticket ────────────────────────────────────────────────────────────
function openAddTicket() {
  // addTicketClient is synced by _syncClientDropdowns() — no manual copy needed.
  const sel = $('addTicketClient');
  // Pre-select the currently filtered client if any
  if (state.clientFilter) sel.value = state.clientFilter;

  $('addTicketKeys').value = '';
  $('addTicketResults').style.display = 'none';
  $('addTicketResults').innerHTML = '';
  $('addTicketModal').style.display = 'flex';
  setTimeout(() => $('addTicketKeys').focus(), 50);
}

function closeAddTicket() {
  $('addTicketModal').style.display = 'none';
}

async function submitAddTicket() {
  const client = $('addTicketClient').value;
  const raw    = $('addTicketKeys').value.trim();
  if (!client) { showToast('Please select a client', 'warn'); return; }
  if (!raw)    { showToast('Please enter at least one ticket key', 'warn'); return; }

  // Parse: split by newlines and commas, clean up
  const keys = raw.split(/[\n,]+/).map(k => k.trim().toUpperCase()).filter(Boolean);
  if (!keys.length) { showToast('No valid ticket keys found', 'warn'); return; }

  const btn = $('addTicketBtn');
  btn.disabled = true;
  btn.textContent = 'Adding…';

  try {
    const res = await fetch('/api/tickets/add', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ keys, client_label: client }),
    });
    const data = await res.json();

    const resultDiv = $('addTicketResults');
    resultDiv.style.display = 'block';

    if (!res.ok) {
      resultDiv.innerHTML = `<div style="color:var(--red)">⚠️ ${escHtml(data.detail || 'Error')}</div>`;
      return;
    }

    const rows = data.results.map(r => {
      if (r.status === 'queued')
        return `<div style="color:var(--green)">✅ <b>${escHtml(r.key)}</b> — ${escHtml(r.summary || '')} <span style="color:var(--text-dim)">[${escHtml(r.rule || 'no rule')}]</span></div>`;
      if (r.status === 'already_queued')
        return `<div style="color:var(--orange)">⚠️ <b>${escHtml(r.key)}</b> — already in queue</div>`;
      return `<div style="color:var(--red)">❌ <b>${escHtml(r.key)}</b> — ${escHtml(r.error || 'error')}</div>`;
    }).join('');

    resultDiv.innerHTML = rows;

    // Refresh job list so newly added tickets appear
    await fetchJobs();

    // Auto-close after 2s if all succeeded
    const allOk = data.results.every(r => r.status === 'queued' || r.status === 'already_queued');
    if (allOk) setTimeout(closeAddTicket, 2000);

  } catch (e) {
    $('addTicketResults').style.display = 'block';
    $('addTicketResults').innerHTML = `<div style="color:var(--red)">⚠️ ${escHtml(e.message)}</div>`;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Add to Queue';
  }
}

// Close on backdrop click
document.addEventListener('click', e => {
  if (e.target === $('addTicketModal'))      closeAddTicket();
  if (e.target === $('sweepModal'))          closeSweep();
  if (e.target === $('bulkTransitionModal')) closeTransitionModal();
});

// ── Sweep ─────────────────────────────────────────────────────────────────
let _sweepClient = null;
let _sweepToQueue = 0;

async function openSweep(label) {
  _sweepClient = label;
  _sweepToQueue = 0;
  $('sweepModalTitle').textContent    = `Sweep Open Tickets — ${label}`;
  $('sweepModalSubtitle').textContent = 'Fetching tickets from Jira…';
  $('sweepPreviewBody').innerHTML     = '<span style="color:var(--text-dim)">⏳ Loading…</span>';
  $('sweepSample').innerHTML          = '';
  $('sweepRunBtn').disabled           = true;
  $('sweepRunBtn').textContent        = 'Queue Tickets';
  $('sweepModal').style.display       = 'flex';

  try {
    const res  = await fetch(`/api/sweep/${encodeURIComponent(label)}/preview`);
    const data = await res.json();
    if (!res.ok) {
      $('sweepPreviewBody').innerHTML = `<span style="color:var(--red)">⚠️ ${escHtml(data.detail || 'Error')}</span>`;
      return;
    }
    _sweepToQueue = data.to_queue;
    $('sweepModalSubtitle').textContent = `Open tickets for ${label} — not Fixed or Risk Accepted`;
    $('sweepPreviewBody').innerHTML = `
      <div style="display:flex;flex-direction:column;gap:6px">
        <div>📋 <b>${data.total}</b> total open tickets found</div>
        <div style="color:var(--green)">✅ <b>${data.auto_queue}</b> have matching scan rules — will be auto-scanned</div>
        <div style="color:var(--yellow,#e6a817)">🖐 <b>${data.queued_manual}</b> have no matching rule — queued for manual review</div>
        <div style="color:var(--text-dim)">⚪ <b>${data.skipped_queued}</b> already in queue — skipped</div>
      </div>`;
    // Show breakdown grouped by rule type
    const byRule = data.by_rule || {};
    const ruleEntries = Object.entries(byRule).sort((a, b) => b[1].length - a[1].length);
    if (ruleEntries.length) {
      $('sweepSample').innerHTML =
        '<div style="margin-bottom:4px;font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px">Breakdown by type:</div>' +
        ruleEntries.map(([rule, tickets]) =>
          `<div style="padding:2px 0">${escHtml(rule)} <span style="color:var(--text-dim)">(${tickets.length})</span></div>`
        ).join('');
    }
    if (data.to_queue > 0) {
      $('sweepRunBtn').disabled    = false;
      $('sweepRunBtn').textContent = `Queue ${data.to_queue} Ticket${data.to_queue !== 1 ? 's' : ''}`;
    } else {
      $('sweepRunBtn').textContent = 'Nothing to Queue';
    }
  } catch (e) {
    $('sweepPreviewBody').innerHTML = `<span style="color:var(--red)">⚠️ ${escHtml(e.message)}</span>`;
  }
}

function closeSweep() {
  $('sweepModal').style.display = 'none';
  _sweepClient = null;
}

async function clearSweepJobs() {
  const count = Object.values(state.jobs).filter(j => j.source === 'sweep' && j.status !== 'scanning').length;
  if (!count) return;
  if (!confirm(`Remove all ${count} sweep ticket(s) from the queue?`)) return;
  state.sweepSearch = '';
  await fetch('/api/sweep/jobs', { method: 'DELETE' });
  await fetchJobs();
}

async function clearManualJobs() {
  const count = Object.values(state.jobs).filter(j => j.source === 'manual' && j.status !== 'scanning').length;
  if (!count) return;
  if (!confirm(`Remove all ${count} manual ticket(s) from the queue?`)) return;
  await fetch('/api/manual/jobs', { method: 'DELETE' });
  await fetchJobs();
}

async function advanceSweepAll() {
  // Only advance swept tickets whose scan is complete with a FIXED verdict and
  // that still need a Jira transition (pre-Remediated). Scanning/queued tickets
  // and non-fixed verdicts are intentionally excluded.
  const candidates = Object.values(state.jobs).filter(j =>
    j.source === 'sweep' &&
    j.status === 'completed' &&
    j.verdict === 'fixed' &&
    needsFastTrack(j)
  );
  if (!candidates.length) return;
  if (!confirm(
    `Advance ${candidates.length} completed+fixed swept ticket${candidates.length !== 1 ? 's' : ''} to Remediated?\n\n` +
    `Each ticket's Jira status will be moved forward using the correct transition chain for its current state.`
  )) return;

  showToast(`⚡ Advancing ${candidates.length} ticket${candidates.length !== 1 ? 's' : ''} to Remediated…`, 'warn', 4000);
  try {
    const res  = await fetch('/api/sweep/advance', { method: 'POST' });
    const data = await res.json();
    await fetchJobs();
    const ok   = data.succeeded.length;
    const fail = data.failed.length;
    if (fail === 0) {
      showToast(`⚡ ${ok} ticket${ok !== 1 ? 's' : ''} advanced to Remediated`, 'success', 6000);
    } else {
      const firstErr = data.failed[0]?.error || 'unknown error';
      showToast(`⚡ ${ok} advanced · ${fail} failed: ${firstErr}`, 'warn', 9000);
    }
  } catch (e) {
    showToast(`Advance All failed: ${e.message}`, 'error');
  }
}

async function stopSweepScans() {
  // Stop all actively scanning sweep jobs
  const scanningIds = Object.values(state.jobs)
    .filter(j => j.source === 'sweep' && j.status === 'scanning')
    .map(j => j.id);
  if (!scanningIds.length) return;

  // Remove these sweep jobs from the global bulk-scan tracker immediately.
  // Without this, _bulkScan holds their IDs and the header stopAllBtn stays
  // lit after the sweep scans stop, which looks like "it started again".
  if (_bulkScan) {
    scanningIds.forEach(id => _bulkScan.ids.delete(id));
    _bulkScan.total = _bulkScan.ids.size;
    if (_bulkScan.ids.size === 0) setBulkScan(null);
    else setBulkScan(_bulkScan);
  }

  showToast(`Stopping ${scanningIds.length} sweep scan${scanningIds.length !== 1 ? 's' : ''}…`, 'warn', 3000);
  await Promise.allSettled(
    scanningIds.map(id => fetch(`/api/jobs/${id}/stop`, { method: 'POST' }))
  );
  await fetchJobs();
}

async function runSweep() {
  if (!_sweepClient) return;
  const label = _sweepClient;
  const btn = $('sweepRunBtn');
  try {
    const res = await fetch(`/api/sweep/${encodeURIComponent(label)}/run`, { method: 'POST' });
    if (!res.ok) {
      const data = await res.json();
      showToast(`Sweep failed: ${data.detail || 'Unknown error'}`, 'error');
      return;
    }
    $('sweepModal').style.display = 'none';
    _sweepClient = null;
    showToast(`Sweeping ${label} — tickets will appear in the queue shortly`, 'info', 5000);
    await fetchJobs();
  } catch (e) {
    showToast(e.message, 'error');
    if (btn) {
      btn.disabled    = false;
      btn.textContent = `Queue ${_sweepToQueue} Ticket${_sweepToQueue !== 1 ? 's' : ''}`;
    }
  }
}

// ── Tab switching ─────────────────────────────────────────────────────────
function switchTab(tab) {
  const isDash       = tab === 'dashboard';
  const isReport     = tab === 'report';
  const isWeekly     = tab === 'weekly';
  const isDuplicates  = tab === 'duplicates';
  const isBatchScan   = tab === 'batchscan';
  const isAssets     = tab === 'assets';
  const isShell      = tab === 'shell';
  const isIntake     = tab === 'intake';
  const isSettings   = tab === 'settings';

  $('tabDashboard').classList.toggle('active', isDash);
  $('tabReport').classList.toggle('active', isReport);
  $('tabWeekly').classList.toggle('active', isWeekly);
  $('tabDuplicates').classList.toggle('active', isDuplicates);
  $('tabBatchScan').classList.toggle('active', isBatchScan);
  $('tabAssets').classList.toggle('active', isAssets);
  $('tabShell').classList.toggle('active', isShell);
  $('tabIntake').classList.toggle('active', isIntake);
  $('tabSettings').classList.toggle('active', isSettings);

  // Dashboard elements
  document.querySelector('.layout').style.display = isDash ? 'flex' : 'none';
  $('logsBar').style.display                      = isDash ? ''     : 'none';
  $('dashboardControls').style.display            = isDash ? ''     : 'none';
  $('dashboardStats').style.display               = isDash ? ''     : 'none';

  // Report view
  const rv = $('reportView');
  rv.style.display       = isReport ? 'flex' : 'none';
  rv.style.flexDirection = 'column';

  // Weekly report view
  const wv = $('weeklyView');
  wv.style.display       = isWeekly ? 'flex' : 'none';
  wv.style.flexDirection = 'column';

  // Duplicates view
  const dv = $('duplicatesView');
  dv.style.display       = isDuplicates ? 'flex' : 'none';
  dv.style.flexDirection = 'column';

  const bsv = $('batchScanView');
  bsv.style.display       = isBatchScan ? 'flex' : 'none';
  bsv.style.flexDirection = 'column';
  if (isBatchScan) initBatchScan();

  // Assets view
  const av = $('assetsView');
  av.style.display       = isAssets ? 'flex' : 'none';
  av.style.flexDirection = 'column';

  // Shell view
  const shv = $('shellView');
  shv.style.display       = isShell ? 'flex' : 'none';
  shv.style.flexDirection = 'column';

  // Settings view
  const sv = $('settingsView');
  sv.style.display       = isSettings ? 'flex' : 'none';
  sv.style.flexDirection = 'column';

  // Intake view
  const iv = $('intakeView');
  if (iv) {
    iv.style.display = isIntake ? 'block' : 'none';
    iv.style.flexDirection = 'column';
  }

  if (isReport) initReportControls();
  if (isWeekly) initWeeklyReportControls();
  if (isAssets) initAssetsTab();
  if (isShell) initShellTab(); else stopTunnelPolling();
  if (isIntake) initIntakeTab();
  if (isSettings) initSettingsTab();
}

// ── Assets Tab ────────────────────────────────────────────────────────────
let _assetsCurrentLabel = '';

function initAssetsTab() {
  const sel = $('assetsClient');
  // Options are kept in sync by _syncClientDropdowns() via fetchClients().
  // Just trigger a load for whatever client is currently selected.
  if (sel.value) { _assetsCurrentLabel = sel.value; loadAssetsForClient(sel.value); }
}

async function onAssetsClientChange() {
  const label = $('assetsClient').value;
  _assetsCurrentLabel = label;
  // Reset the Nessus folder checklist and scan list
  _nessusFolders = [];
  _nessusLoadedFolders.clear();
  $('nessusFolderList').innerHTML = '<span style="color:var(--text-dim)">Click "Load Folders" to see this client\'s Nessus folders</span>';
  $('nessusScanList').innerHTML = '<span style="color:var(--text-dim)">Check a folder to see its scans</span>';
  $('nessusPullBtn').disabled = true;
  $('nessusPullStatus').textContent = '';
  $('assetsResults').innerHTML = '';
  if (label) await loadAssetsForClient(label);
}

async function loadAssetsForClient(label) {
  try {
    const res  = await fetch(`/api/assets/${encodeURIComponent(label)}`);
    const data = await res.json();
    $('assetsTextarea').value = (data.entries || []).join('\n');
    const count = (data.entries || []).length;
    $('assetsSaveStatus').textContent = data.updated_at
      ? `${count} entries · saved ${data.updated_at.slice(0, 10)}`
      : 'No asset list saved yet';
  } catch (e) {
    $('assetsSaveStatus').textContent = 'Failed to load';
  }
}

async function saveAssets() {
  const label = $('assetsClient').value;
  if (!label) { showToast('Select a client first', 'warn'); return; }
  const raw     = $('assetsTextarea').value;
  const entries = raw.split(/[\n,]+/).map(s => s.trim()).filter(Boolean);
  if (!entries.length) { showToast('No entries to save', 'warn'); return; }

  try {
    const res = await fetch(`/api/assets/${encodeURIComponent(label)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ entries }),
    });
    const data = await res.json();
    if (!res.ok) { showToast(data.detail || 'Error saving', 'error'); return; }
    $('assetsSaveStatus').textContent = `${data.saved} entries saved`;
    showToast(`Asset list saved — ${data.saved} IPs/subnets`, 'success');
  } catch (e) {
    showToast(e.message, 'error');
  }
}

// Cache of {id, name} for the currently loaded client, and the set of
// folder ids whose scans are currently expanded in the shared scan list —
// lets any number of folders (not just two) be checked at once, with their
// scans combined into one list for Pull & Compare.
let _nessusFolders = [];
let _nessusLoadedFolders = new Set();

async function loadNessusFolders() {
  const label = $('assetsClient').value;
  if (!label) { showToast('Select a client first', 'warn'); return; }

  const folderListDiv = $('nessusFolderList');
  folderListDiv.innerHTML = '<span style="color:var(--text-dim)">⏳ Loading…</span>';
  $('nessusScanList').innerHTML = '<span style="color:var(--text-dim)">Check a folder to see its scans</span>';
  _nessusLoadedFolders.clear();
  _updateNessusPullBtn();

  try {
    const res  = await fetch(`/api/nessus/${encodeURIComponent(label)}/folders`);
    const data = await res.json();
    if (!res.ok) {
      folderListDiv.innerHTML = `<span style="color:var(--red)">${escHtml(data.detail || 'Failed to load folders')}</span>`;
      return;
    }
    _nessusFolders = data.folders || [];
    if (!_nessusFolders.length) {
      folderListDiv.innerHTML = '<span style="color:var(--text-dim)">No folders found in Nessus</span>';
      showToast('No folders found in Nessus', 'warn');
      return;
    }
    folderListDiv.innerHTML = _nessusFolders.map(f => `
      <label style="display:flex;align-items:center;gap:8px;padding:4px 2px;cursor:pointer;border-bottom:1px solid var(--border)">
        <input type="checkbox" class="nessus-folder-check" value="${f.id}" onchange="onNessusFolderToggle(${f.id}, this.checked)">
        <span>${escHtml(f.name)}</span>
      </label>`).join('');
  } catch (e) {
    folderListDiv.innerHTML = `<span style="color:var(--red)">${escHtml(e.message)}</span>`;
  }
}

function _nessusFolderHeaderHtml(folderId) {
  const folder = _nessusFolders.find(f => f.id === folderId);
  const name = folder ? folder.name : `Folder ${folderId}`;
  return `<div style="font-size:10px;font-weight:700;color:var(--text-dim);text-transform:uppercase;letter-spacing:0.5px;margin:6px 0 2px">${escHtml(name)}</div>`;
}

// Checking a folder appends its scans (tagged with the folder id) into the
// shared #nessusScanList; unchecking removes just that folder's rows —
// scans from every currently-checked folder stay combined in one list.
async function onNessusFolderToggle(folderId, checked) {
  const label   = $('assetsClient').value;
  const listDiv = $('nessusScanList');

  if (!checked) {
    listDiv.querySelectorAll(`[data-folder-id="${folderId}"]`).forEach(el => el.remove());
    _nessusLoadedFolders.delete(folderId);
    if (!listDiv.children.length) {
      listDiv.innerHTML = '<span style="color:var(--text-dim)">Check a folder to see its scans</span>';
    }
    _updateNessusPullBtn();
    return;
  }

  if (listDiv.children.length === 1 && listDiv.children[0].tagName === 'SPAN') {
    listDiv.innerHTML = '';
  }

  const group = document.createElement('div');
  group.dataset.folderId = folderId;
  group.innerHTML = _nessusFolderHeaderHtml(folderId) + '<span style="color:var(--text-dim)">⏳ Loading scans…</span>';
  listDiv.appendChild(group);
  _nessusLoadedFolders.add(folderId);

  // Helper: returns true if this fetch is still relevant — the group element
  // is still attached to the DOM and the user hasn't switched to a different
  // client.  If either condition fails the request was superseded (folder
  // unchecked, Load Folders clicked, client changed) and we must discard the
  // result rather than write to a detached/wrong element.
  const isCurrent = () => listDiv.contains(group) && $('assetsClient').value === label;

  try {
    const res  = await fetch(`/api/nessus/${encodeURIComponent(label)}/scans?folder_id=${folderId}`);
    const data = await res.json();

    if (!isCurrent()) return;   // ← stale: DOM was reset while request was in-flight

    if (!res.ok) {
      group.innerHTML = _nessusFolderHeaderHtml(folderId) + `<span style="color:var(--red)">${escHtml(data.detail || 'Error')}</span>`;
      return;
    }
    const scans = data.scans || [];
    if (!scans.length) {
      group.innerHTML = _nessusFolderHeaderHtml(folderId) + '<span style="color:var(--text-dim)">No scans in this folder</span>';
      return;
    }
    group.innerHTML = _nessusFolderHeaderHtml(folderId) + scans.map(s => {
      const dt = s.last_modification_date
        ? new Date(s.last_modification_date * 1000).toLocaleDateString()
        : '';
      const stColor = s.status === 'completed' ? 'var(--green)' : 'var(--text-dim)';
      const hostCount = (s.total_hosts != null && s.total_hosts > 0)
        ? `<span style="color:var(--cyan);flex-shrink:0;font-size:10px" title="${s.total_hosts} hosts">🖥 ${s.total_hosts}</span>`
        : '';
      return `
        <label style="display:flex;align-items:center;gap:8px;padding:4px 2px;cursor:pointer;border-bottom:1px solid var(--border)">
          <input type="checkbox" class="nessus-scan-check" value="${s.id}" data-hosts="${s.total_hosts || 0}" onchange="_updateNessusPullBtn()" ${s.status === 'completed' ? 'checked' : ''}>
          <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(s.name)}</span>
          ${hostCount}
          <span style="color:${stColor};flex-shrink:0;font-size:10px">${escHtml(s.status)}</span>
          ${dt ? `<span style="color:var(--text-dim);flex-shrink:0;font-size:10px">${dt}</span>` : ''}
        </label>`;
    }).join('');
  } catch (e) {
    if (isCurrent()) {
      group.innerHTML = _nessusFolderHeaderHtml(folderId) + `<span style="color:var(--red)">${escHtml(e.message)}</span>`;
    }
  } finally {
    _updateNessusPullBtn();
  }
}

let _nessusHostCountDebounce = null;
function _updateNessusPullBtn() {
  const checked = [...document.querySelectorAll('.nessus-scan-check:checked')];
  const any = checked.length > 0;
  $('nessusPullBtn').disabled = !any;
  if (_nessusHostCountDebounce) { clearTimeout(_nessusHostCountDebounce); _nessusHostCountDebounce = null; }
  if (!any) {
    $('nessusHostCount').textContent = '';
    return;
  }

  // Fast path: the scan list already gives us total_hosts per scan (stored in
  // the checkbox's data-hosts attribute). Sum those on the client instantly —
  // no server round-trip, no re-fetching full scan details over SSH.
  let knownSum = 0;
  const unknownIds = [];
  for (const cb of checked) {
    const h = parseInt(cb.getAttribute('data-hosts') || '0', 10);
    if (h > 0) knownSum += h;
    else unknownIds.push(parseInt(cb.value, 10));  // incomplete/unknown → ask server
  }

  // Every selected scan had a known count → done, zero network calls.
  if (unknownIds.length === 0) {
    $('nessusHostCount').textContent = `🖥 ${knownSum.toLocaleString()} hosts in selected scans`;
    return;
  }

  // Some scans have no cached count (e.g. incomplete runs needing a history
  // fallback). Show what we know immediately, then resolve just the unknowns.
  $('nessusHostCount').textContent = knownSum > 0
    ? `🖥 ${knownSum.toLocaleString()}+ hosts (counting ${unknownIds.length} scan${unknownIds.length > 1 ? 's' : ''}…)`
    : '🖥 counting hosts…';

  const label = $('assetsClient').value;
  _nessusHostCountDebounce = setTimeout(() => {
    fetch(`/api/nessus/${encodeURIComponent(label)}/host-count`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scan_ids: unknownIds }),
    })
    .then(r => r.json())
    .then(d => {
      const total = knownSum + (d.total_hosts || 0);
      $('nessusHostCount').textContent = `🖥 ${total.toLocaleString()} hosts in selected scans`;
    })
    .catch(() => {
      $('nessusHostCount').textContent = knownSum > 0
        ? `🖥 ${knownSum.toLocaleString()}+ hosts in selected scans`
        : '';
    });
  }, 400);
}

const NESSUS_PORT = 8834;

async function _waitForTunnelListening(tunnelId, timeoutMs = 8000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const resp = await fetch('/api/tunnels');
    if (resp.ok) {
      const tunnels = await resp.json();
      const t = tunnels.find(t => t.id === tunnelId);
      if (!t) return null;
      if (t.status === 'listening') return t;
      if (t.status === 'error') return t;
    }
    await new Promise(r => setTimeout(r, 400));
  }
  return null;
}

async function openNessus() {
  const label = $('assetsClient').value;
  if (!label) { showToast('Select a client first', 'warn'); return; }

  // Open the tab synchronously, inside the click handler, so the browser
  // still treats it as user-initiated — any awaited work happens after,
  // and we just redirect this already-open tab once the URL is known.
  // (window.open() after an await is treated as a non-user-initiated
  // popup and gets blocked.)
  const win = window.open('about:blank', '_blank');
  if (!win) {
    showToast('Pop-up blocked — allow pop-ups for this site and try again', 'error');
    return;
  }

  let tunnels;
  try {
    const resp = await fetch('/api/tunnels');
    tunnels = resp.ok ? await resp.json() : [];
  } catch (e) {
    tunnels = [];
  }

  const existing = tunnels.find(t =>
    t.label === label && t.target_host === '127.0.0.1' &&
    t.target_port === NESSUS_PORT && t.status === 'listening'
  );
  if (existing) {
    win.location.href = `https://localhost:${existing.local_port}`;
    return;
  }

  showToast('Starting tunnel to Nessus…', 'info');

  async function tryStart(localPort) {
    const resp = await fetch('/api/tunnels', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        label, target_host: '127.0.0.1', target_port: NESSUS_PORT, local_port: localPort,
      }),
    });
    const data = await resp.json();
    return { ok: resp.ok, data };
  }

  let { ok, data } = await tryStart(NESSUS_PORT);
  if (!ok) {
    // Local port 8834 is probably already taken (e.g. another colleague's
    // tunnel) — fall back to letting the OS pick any free local port.
    ({ ok, data } = await tryStart(0));
  }
  if (!ok) {
    showToast(data.detail || 'Failed to start tunnel to Nessus', 'error');
    win.close();
    return;
  }

  const tunnel = await _waitForTunnelListening(data.id);
  if (!tunnel || tunnel.status !== 'listening') {
    showToast((tunnel && tunnel.error) || 'Tunnel did not come up in time', 'error');
    win.close();
    return;
  }
  win.location.href = `https://localhost:${tunnel.local_port}`;
  refreshTunnels();
}

async function pullNessus() {
  const label = $('assetsClient').value;
  if (!label) { showToast('Select a client first', 'warn'); return; }

  const checked = [...document.querySelectorAll('.nessus-scan-check:checked')];
  const scanIds = checked.map(cb => parseInt(cb.value, 10));
  if (!scanIds.length) { showToast('No scans selected', 'warn'); return; }

  const btn    = $('nessusPullBtn');
  const status = $('nessusPullStatus');
  btn.disabled    = true;
  btn.textContent = 'Pulling…';
  status.textContent = `Fetching hosts from ${scanIds.length} scan(s)…`;

  try {
    const res = await fetch(`/api/nessus/${encodeURIComponent(label)}/pull`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scan_ids: scanIds }),
    });
    const data = await res.json();
    if (!res.ok) {
      showToast(data.detail || 'Pull failed', 'error');
      status.textContent = '';
      return;
    }
    status.textContent = `${data.total_hosts_pulled} hosts pulled`;
    if (data.errors && data.errors.length) {
      const detail = data.errors.slice(0, 2).join(' | ');
      const more   = data.errors.length > 2 ? ` (+${data.errors.length - 2} more)` : '';
      showToast(`Partial results — ${data.errors.length} scan error(s): ${detail}${more}`, 'warn', 12000);
    }
    renderAssetsResults(data);
  } catch (e) {
    showToast(e.message, 'error');
    status.textContent = '';
  } finally {
    btn.disabled    = false;
    btn.textContent = 'Pull Hosts';
  }
}

function renderAssetsResults(data) {
  const c = data.counts || {};

  function ipChips(ips, color) {
    if (!ips || !ips.length) return '<span style="color:var(--text-dim);font-size:11px">None</span>';
    const show = ips.slice(0, 150);
    const more = ips.length - show.length;
    return show.map(ip =>
      `<span style="display:inline-block;margin:2px;padding:1px 7px;background:var(--bg);border:1px solid var(--border);border-radius:3px;font-family:monospace;font-size:11px;color:${color}">${escHtml(ip)}</span>`
    ).join('') + (more ? `<span style="color:var(--text-dim);font-size:11px"> …+${more} more</span>` : '');
  }

  // Store result on the element for the download handler
  $('assetsResults')._lastResult = data;

  const hasUnresolved = (c.unresolved || 0) > 0;
  // Scope coverage: how many provided scope entries had at least one host found.
  const coverage = (c.total_scope || 0) > 0
    ? `${c.reachable_scope || 0} of ${c.total_scope} scope entries reached`
    : '';

  const unresolvedSummaryCard = hasUnresolved ? `
      <div class="report-card" style="padding:14px">
        <div style="font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px">Unresolved</div>
        <div style="font-size:32px;font-weight:700;color:var(--red)">${c.unresolved}</div>
        <div style="font-size:11px;color:var(--text-dim)">scanned hosts reported by name (not an IP) — match manually</div>
      </div>` : '';

  const unresolvedDetailCard = hasUnresolved ? `
      <div class="report-card" style="padding:14px">
        <div style="font-size:11px;font-weight:600;color:var(--red);margin-bottom:10px">❓ Unresolved — Not an IP (${c.unresolved})</div>
        <div style="line-height:2">${ipChips(data.unresolved, 'var(--red)')}</div>
      </div>` : '';

  const summaryCols = hasUnresolved ? 4 : 3;

  const html = `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
      <div>
        <span style="font-size:13px;font-weight:600;color:var(--text)">Cross-Reference Results</span>
        ${coverage ? `<span style="font-size:11px;color:var(--text-dim);margin-left:10px">${coverage} · ${c.total_scanned || 0} hosts scanned</span>` : ''}
      </div>
      <button class="btn btn-secondary btn-sm" onclick="downloadAssetsCSV()">⬇ Download CSV</button>
    </div>

    <div style="display:grid;grid-template-columns:repeat(${summaryCols},1fr);gap:12px;margin-bottom:16px">
      <div class="report-card" style="padding:14px">
        <div style="font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px">Reachable (In Scope)</div>
        <div style="font-size:32px;font-weight:700;color:var(--green)">${c.reachable || 0}</div>
        <div style="font-size:11px;color:var(--text-dim)">in-scope hosts found by Nessus</div>
      </div>
      <div class="report-card" style="padding:14px">
        <div style="font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px">Not Reachable (In Scope)</div>
        <div style="font-size:32px;font-weight:700;color:var(--orange)">${c.not_reachable || 0}</div>
        <div style="font-size:11px;color:var(--text-dim)">scope entries (IPs/subnets) with no hosts found</div>
      </div>
      <div class="report-card" style="padding:14px">
        <div style="font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px">Out of Scope</div>
        <div style="font-size:32px;font-weight:700;color:var(--purple)">${c.out_of_scope || 0}</div>
        <div style="font-size:11px;color:var(--text-dim)">hosts Nessus found outside scope</div>
      </div>
      ${unresolvedSummaryCard}
    </div>

    <div style="display:grid;grid-template-columns:repeat(${summaryCols},1fr);gap:12px">
      <div class="report-card" style="padding:14px">
        <div style="font-size:11px;font-weight:600;color:var(--green);margin-bottom:10px">✅ Reachable — In Scope (${c.reachable || 0})</div>
        <div style="line-height:2">${ipChips(data.reachable, 'var(--green)')}</div>
      </div>
      <div class="report-card" style="padding:14px">
        <div style="font-size:11px;font-weight:600;color:var(--orange);margin-bottom:10px">⚠️ Not Reachable — In Scope (${c.not_reachable || 0})</div>
        <div style="line-height:2">${ipChips(data.not_reachable, 'var(--orange)')}</div>
      </div>
      <div class="report-card" style="padding:14px">
        <div style="font-size:11px;font-weight:600;color:var(--purple);margin-bottom:10px">🔍 Out of Scope (${c.out_of_scope || 0})</div>
        <div style="line-height:2">${ipChips(data.out_of_scope, 'var(--purple)')}</div>
      </div>
      ${unresolvedDetailCard}
    </div>`;

  $('assetsResults').innerHTML = html;
  $('assetsResults').scrollIntoView({ behavior: 'smooth' });
}

function downloadAssetsCSV() {
  const data = $('assetsResults')._lastResult;
  if (!data) return;

  const rows = [['IP / Subnet', 'Category']];
  (data.reachable     || []).forEach(ip => rows.push([ip, 'Reachable - In Scope']));
  (data.not_reachable || []).forEach(ip => rows.push([ip, 'Not Reachable - In Scope']));
  (data.out_of_scope  || []).forEach(ip => rows.push([ip, 'Out of Scope']));
  (data.unresolved    || []).forEach(ip => rows.push([ip, 'Unresolved - Not an IP']));

  const csv  = rows.map(r => r.join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `assets_${_assetsCurrentLabel || 'export'}_${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ── Nessus CSV export (bulk ZIP download) ────────────────────────────────────


// ── Monthly Report ────────────────────────────────────────────────────────
let _reportListenersAdded = false;
function initReportControls() {
  // Options are kept in sync by _syncClientDropdowns() via fetchClients().
  // Only attach the change listeners once.
  if (!_reportListenersAdded) {
    $('reportClient').addEventListener('change', generateReport);
    $('reportMonth').addEventListener('change', generateReport);
    _reportListenersAdded = true;
  }

  // Set max month to last completed month
  const inp = $('reportMonth');
  const now = new Date();
  const prevMonth = new Date(now.getFullYear(), now.getMonth() - 1, 1);
  const maxVal = `${prevMonth.getFullYear()}-${String(prevMonth.getMonth() + 1).padStart(2, '0')}`;
  inp.max = maxVal;
  if (!inp.value) inp.value = maxVal;
}

async function generateReport() {
  const client = $('reportClient').value;
  const month  = $('reportMonth').value;

  if (!client) { showToast('Please select a client', 'warn'); return; }
  if (!month)  { showToast('Please select a month', 'warn');  return; }

  const btn = $('reportGenBtn');
  btn.disabled = true;
  btn.textContent = 'Loading…';
  $('reportResults').innerHTML = '<div class="report-loading">⏳ Fetching data from Jira…</div>';

  try {
    const res = await fetch(`/api/report?client=${encodeURIComponent(client)}&month=${encodeURIComponent(month)}`);
    const data = await res.json();
    if (!res.ok) {
      $('reportResults').innerHTML = `<div class="report-error">⚠️ ${escHtml(data.detail || 'Unknown error')}</div>`;
      return;
    }
    renderReport(data);
  } catch (e) {
    $('reportResults').innerHTML = `<div class="report-error">⚠️ Request failed: ${escHtml(e.message)}</div>`;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Generate Report';
  }
}

function renderReport(d) {
  const [year, mon] = d.month.split('-');
  const monthName = new Date(+year, +mon - 1, 1).toLocaleString('default', { month: 'long' });
  const title = `${monthName} ${year} — ${d.client}`;

  function val(n) {
    return n === -1 ? '<span style="color:var(--text-dim)">ERR</span>' : n;
  }

  function card(header, sub, rows) {
    const rowsHtml = rows.map(([label, value, cls]) => `
      <div class="report-row ${cls || ''}">
        <span class="report-row-label">${label}</span>
        <span class="report-row-value">${val(value)}</span>
      </div>`).join('');
    const subHtml = sub ? `<div class="report-card-sub">${escHtml(sub)}</div>` : '';
    return `
      <div class="report-card">
        <div class="report-card-header">${escHtml(header)}${subHtml}</div>
        <div class="report-card-body">${rowsHtml}</div>
      </div>`;
  }

  const nt = d.new_tickets;
  const ot = d.open_tickets;
  const nv = d.new_vulnerabilities || { is_sample: false, items: [] };

  function ratingClass(rating) {
    const v = (rating || '').toLowerCase();
    return ['critical', 'high', 'medium', 'low'].includes(v) ? `rating-${v}` : '';
  }

  function statusClass(it) {
    const s = (it.status || '').toLowerCase().trim();
    if (['fixed', 'closed', 'done', 'resolved'].includes(s)) return 'status-fixed';
    if (s === 'not fixed') return 'status-not-fixed';
    if (['risk accepted', 'accepted risk'].includes(s)) return 'status-risk-accepted';
    if (['remediated', 'in progress'].includes(s)) return 'status-progress';
    if (s === 'reported') return 'status-reported';
    return 'status-other';
  }

  function vulnTable() {
    const sub = nv.is_sample
      ? `No tickets created in ${monthName} ${year} — random sample of currently open vulnerabilities`
      : `Created in ${monthName} ${year}`;
    const bodyHtml = nv.items.length
      ? nv.items.map(it => `
        <tr>
          <td>${escHtml(it.vuln_name)}</td>
          <td class="vuln-key">${escHtml(it.key)}</td>
          <td class="vuln-ip">${escHtml(it.ip || '—')}</td>
          <td class="vuln-rating ${ratingClass(it.rating)}">${escHtml(it.rating || '—')}</td>
          <td class="vuln-status ${statusClass(it)}" title="${escHtml(it.status_label || '')}">${escHtml(it.status || '—')}</td>
        </tr>`).join('')
      : `<tr><td colspan="5" class="report-vuln-empty">No vulnerabilities to show</td></tr>`;
    return `
      <div class="report-vuln-card">
        <div class="report-card-header">New Discovered Vulnerabilities<div class="report-card-sub">${escHtml(sub)}</div></div>
        <table class="report-vuln-table">
          <thead><tr><th>Vulnerability</th><th>Issue Key</th><th>IP Address</th><th>Rating</th><th>Status</th></tr></thead>
          <tbody>${bodyHtml}</tbody>
        </table>
      </div>`;
  }

  function osTable(data) {
    const osData = data || d.os_breakdown || { items: [] };
    const items = osData.items;
    if (!items || !items.length) return '';
    const bodyHtml = items.map(it => `
      <tr>
        <td>${escHtml(it.os)}</td>
        <td style="text-align:right">${it.issues}</td>
        <td style="text-align:right">${it.ips}</td>
      </tr>`).join('');
    return `
      <div class="report-vuln-card" style="margin-top:20px">
        <div class="report-card-header">Open issues by OS</div>
        <table class="report-vuln-table">
          <thead><tr><th>OS</th><th style="text-align:right">Issues</th><th style="text-align:right">IPs</th></tr></thead>
          <tbody>${bodyHtml}</tbody>
        </table>
      </div>`;
  }

  const html = `
    <div style="margin-bottom:18px;font-size:15px;font-weight:700;color:var(--text)">${escHtml(title)}</div>

    ${vulnTable()}

    <div class="report-grid">

      ${card('New Tickets', `Created in ${monthName} ${year}`, [
        ['New Tickets',  nt.total,    'row-total'],
        ['Critical',     nt.critical, 'row-critical'],
        ['High',         nt.high,     'row-high'],
        ['Medium',       nt.medium,   'row-medium'],
        ['Low',          nt.low,      'row-low'],
      ])}

      ${card('Fixed This Month', `Resolved in ${monthName} ${year}`, [
        ['Fixed & Closed', d.fixed_this_month, 'row-total'],
      ])}

      ${card('Total Open Tickets', `As of ${monthName} ${d.period.last_day}, ${year}`, [
        ['Total Open',    ot.total,         'row-total'],
        ['Critical',      ot.critical,      'row-critical'],
        ['High',          ot.high,          'row-high'],
        ['Medium',        ot.medium,        'row-medium'],
        ['Low',           ot.low,           'row-low'],
        ['Risk Accepted', ot.risk_accepted, 'row-risk'],
      ])}

    </div>

    <div class="report-footer">
      <span class="report-footer-label">Total Fixed as of ${monthName} ${d.period.last_day}, ${year}</span>
      <span class="report-footer-value">${val(d.total_fixed_to_date)}</span>
    </div>
    ${osTable()}
  `;

  $('reportResults').innerHTML = html;
}

// ── Weekly Report ─────────────────────────────────────────────────────────
let _weeklyListenersAdded = false;

function initWeeklyReportControls() {
  if (!_weeklyListenersAdded) {
    $('weeklyClient').addEventListener('change', generateWeeklyReport);
    $('weeklyWeek').addEventListener('change', generateWeeklyReport);
    _weeklyListenersAdded = true;
  }

  // Max date = last Sunday that has fully passed
  // (dow 0=Sun: go back 7; Mon-Sat: go back dow days to reach last Sun)
  const inp = $('weeklyWeek');
  const today = new Date();
  const dow = today.getDay();
  const lastSunday = new Date(today);
  lastSunday.setDate(today.getDate() - (dow === 0 ? 7 : dow));
  const maxDate = lastSunday.toISOString().slice(0, 10);
  inp.max = maxDate;
  if (!inp.value) inp.value = maxDate;
}

async function generateWeeklyReport() {
  const client = $('weeklyClient').value;
  const day    = $('weeklyWeek').value;

  if (!client) { showToast('Please select a client', 'warn'); return; }
  if (!day)    { showToast('Please select a date',   'warn'); return; }

  const btn = $('weeklyGenBtn');
  btn.disabled = true;
  btn.textContent = 'Loading…';
  $('weeklyResults').innerHTML = '<div class="report-loading">⏳ Fetching data from Jira…</div>';

  try {
    const res = await fetch(`/api/report/weekly?client=${encodeURIComponent(client)}&day=${encodeURIComponent(day)}`);
    const data = await res.json();
    if (!res.ok) {
      $('weeklyResults').innerHTML = `<div class="report-error">⚠️ ${escHtml(data.detail || 'Unknown error')}</div>`;
      return;
    }
    renderWeeklyReport(data);
  } catch (e) {
    $('weeklyResults').innerHTML = `<div class="report-error">⚠️ Request failed: ${escHtml(e.message)}</div>`;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Generate Report';
  }
}

function renderWeeklyReport(d) {
  const p = d.period;
  // Format e.g. "Mon 8 Jun" / "Sun 14 Jun 2026"
  const fmtDate = iso => {
    const dt = new Date(iso + 'T00:00:00');
    return dt.toLocaleDateString('default', { weekday: 'short', day: 'numeric', month: 'short' });
  };
  const endYear = new Date(p.week_end + 'T00:00:00').getFullYear();
  const title = `Week of ${fmtDate(p.week_start)} – ${fmtDate(p.week_end)} ${endYear} — ${d.client}`;

  function val(n) {
    return n === -1 ? '<span style="color:var(--text-dim)">ERR</span>' : n;
  }

  function card(header, sub, rows) {
    const rowsHtml = rows.map(([label, value, cls]) => `
      <div class="report-row ${cls || ''}">
        <span class="report-row-label">${label}</span>
        <span class="report-row-value">${val(value)}</span>
      </div>`).join('');
    const subHtml = sub ? `<div class="report-card-sub">${escHtml(sub)}</div>` : '';
    return `
      <div class="report-card">
        <div class="report-card-header">${escHtml(header)}${subHtml}</div>
        <div class="report-card-body">${rowsHtml}</div>
      </div>`;
  }

  const nt = d.new_tickets;
  const ot = d.open_tickets;
  const nv = d.new_vulnerabilities || { is_sample: false, items: [] };

  function ratingClass(rating) {
    const v = (rating || '').toLowerCase();
    return ['critical', 'high', 'medium', 'low'].includes(v) ? `rating-${v}` : '';
  }

  function statusClass(it) {
    const s = (it.status || '').toLowerCase().trim();
    if (['fixed', 'closed', 'done', 'resolved'].includes(s)) return 'status-fixed';
    if (s === 'not fixed') return 'status-not-fixed';
    if (['risk accepted', 'accepted risk'].includes(s)) return 'status-risk-accepted';
    if (['remediated', 'in progress'].includes(s)) return 'status-progress';
    if (s === 'reported') return 'status-reported';
    return 'status-other';
  }

  function vulnTable() {
    const sub = nv.is_sample
      ? `No tickets created this week — random sample of currently open vulnerabilities`
      : `Created ${fmtDate(p.week_start)} – ${fmtDate(p.week_end)}`;
    const bodyHtml = nv.items.length
      ? nv.items.map(it => `
        <tr>
          <td>${escHtml(it.vuln_name)}</td>
          <td class="vuln-key">${escHtml(it.key)}</td>
          <td class="vuln-ip">${escHtml(it.ip || '—')}</td>
          <td class="vuln-rating ${ratingClass(it.rating)}">${escHtml(it.rating || '—')}</td>
          <td class="vuln-status ${statusClass(it)}" title="${escHtml(it.status_label || '')}">${escHtml(it.status || '—')}</td>
        </tr>`).join('')
      : `<tr><td colspan="5" class="report-vuln-empty">No vulnerabilities to show</td></tr>`;
    return `
      <div class="report-vuln-card">
        <div class="report-card-header">New Discovered Vulnerabilities<div class="report-card-sub">${escHtml(sub)}</div></div>
        <table class="report-vuln-table">
          <thead><tr><th>Vulnerability</th><th>Issue Key</th><th>IP Address</th><th>Rating</th><th>Status</th></tr></thead>
          <tbody>${bodyHtml}</tbody>
        </table>
      </div>`;
  }

  function osTable(data) {
    const osData = data || d.os_breakdown || { items: [] };
    const items = osData.items;
    if (!items || !items.length) return '';
    const bodyHtml = items.map(it => `
      <tr>
        <td>${escHtml(it.os)}</td>
        <td style="text-align:right">${it.issues}</td>
        <td style="text-align:right">${it.ips}</td>
      </tr>`).join('');
    return `
      <div class="report-vuln-card" style="margin-top:20px">
        <div class="report-card-header">Open issues by OS</div>
        <table class="report-vuln-table">
          <thead><tr><th>OS</th><th style="text-align:right">Issues</th><th style="text-align:right">IPs</th></tr></thead>
          <tbody>${bodyHtml}</tbody>
        </table>
      </div>`;
  }

  const html = `
    <div style="margin-bottom:18px;font-size:15px;font-weight:700;color:var(--text)">${escHtml(title)}</div>

    ${vulnTable()}

    <div class="report-grid">

      ${card('New Tickets', `Created ${fmtDate(p.week_start)} – ${fmtDate(p.week_end)}`, [
        ['New Tickets', nt.total,    'row-total'],
        ['Critical',   nt.critical, 'row-critical'],
        ['High',       nt.high,     'row-high'],
        ['Medium',     nt.medium,   'row-medium'],
        ['Low',        nt.low,      'row-low'],
      ])}

      ${card('Fixed This Week', `Resolved ${fmtDate(p.week_start)} – ${fmtDate(p.week_end)}`, [
        ['Fixed & Closed', d.fixed_this_week, 'row-total'],
      ])}

      ${card('Total Open Tickets', `As of ${fmtDate(p.week_end)}`, [
        ['Total Open',    ot.total,         'row-total'],
        ['Critical',      ot.critical,      'row-critical'],
        ['High',          ot.high,          'row-high'],
        ['Medium',        ot.medium,        'row-medium'],
        ['Low',           ot.low,           'row-low'],
        ['Risk Accepted', ot.risk_accepted, 'row-risk'],
      ])}

    </div>

    <div class="report-footer">
      <span class="report-footer-label">Total Fixed as of ${fmtDate(p.week_end)}</span>
      <span class="report-footer-value">${val(d.total_fixed_to_date)}</span>
    </div>
    ${osTable()}
  `;

  $('weeklyResults').innerHTML = html;
}

// ── Duplicate Detection ───────────────────────────────────────────────────

async function findDuplicates() {
  const client = $('duplicatesClient').value;
  if (!client) { showToast('Please select a client', 'warn'); return; }

  const btn = $('duplicatesFindBtn');
  btn.disabled = true;
  btn.textContent = 'Searching…';
  $('duplicatesResults').innerHTML = '<div class="report-loading">⏳ Scanning Jira for duplicate tickets…</div>';

  try {
    const res  = await fetch(`/api/duplicates?client=${encodeURIComponent(client)}`);
    const data = await res.json();
    if (!res.ok) {
      $('duplicatesResults').innerHTML = `<div class="report-error">⚠️ ${escHtml(data.detail || 'Unknown error')}</div>`;
      return;
    }
    _currentDuplicatesData = data;
    renderDuplicates(data);
  } catch (e) {
    $('duplicatesResults').innerHTML = `<div class="report-error">⚠️ Request failed: ${escHtml(e.message)}</div>`;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Find Duplicates';
  }
}

// Holds all duplicate (non-keep) tickets from the last scan
let _dupUrlsToClose = [];
// Holds all keep (old) tickets from the last scan
let _keepUrls = [];
// Maps tester name → array of {key, url} for their duplicate tickets
let _dupByTester = {};
// Sorted [name, tickets] pairs — index used by per-tester open buttons
let _dupTesterList = [];
// Holds the raw data for Excel export
let _currentDuplicatesData = null;

function renderDuplicates(data) {
  const container = $('duplicatesResults');

  if (data.total_groups === 0) {
    container.innerHTML = `
      <div class="report-card" style="padding:20px;text-align:center;color:var(--text-dim)">
        ✅ No duplicate tickets found for <strong>${escHtml(data.client)}</strong>
      </div>`;
    _dupUrlsToClose = [];
    _keepUrls = [];
    _dupByTester = {};
    _dupTesterList = [];
    _currentDuplicatesData = null;
    return;
  }

  // Collect every duplicate (non-keep) and keep (old) — build global lists and per-tester map
  _dupUrlsToClose = [];
  _keepUrls = [];
  _dupByTester = {};
  data.groups.forEach(g => {
    g.tickets.forEach(t => {
      if (t.key !== g.keep) {
        _dupUrlsToClose.push({ key: t.key, url: t.jira_url });
        const name = t.tester || t.reporter || 'Unknown';
        if (!_dupByTester[name]) _dupByTester[name] = [];
        _dupByTester[name].push({ key: t.key, url: t.jira_url });
      } else {
        _keepUrls.push({ key: t.key, url: t.jira_url });
      }
    });
  });

  // Tester breakdown — sorted by count desc, with per-tester open button
  // Store sorted entries so buttons can reference by index (avoids quoting issues in onclick)
  _dupTesterList = Object.entries(_dupByTester).sort((a, b) => b[1].length - a[1].length);

  const reporterRows = _dupTesterList
    .map(([name, tickets], idx) => `
      <tr>
        <td style="padding:5px 10px 5px 0;color:var(--text)">${escHtml(name)}</td>
        <td style="padding:5px 0;font-weight:600;color:var(--orange);text-align:right">${tickets.length}</td>
        <td style="padding:5px 0 5px 8px;color:var(--text-dim);font-size:11px">
          ticket${tickets.length !== 1 ? 's' : ''}
        </td>
        <td style="padding:5px 0 5px 12px">
          <button class="btn btn-sm btn-secondary"
                  onclick="openDuplicatesForTester(${idx})"
                  style="font-size:11px;white-space:nowrap">
            🔗 Open ${tickets.length} in Jira
          </button>
        </td>
      </tr>`).join('');

  const n = _dupUrlsToClose.length;
  const k = _keepUrls.length;
  const summary = `
    <div style="margin-bottom:20px">
      <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-bottom:14px">
        <div>
          <span style="font-size:15px;font-weight:700;color:var(--text)">
            ${data.total_groups} duplicate group${data.total_groups !== 1 ? 's' : ''}
            &nbsp;·&nbsp; ${data.total_duplicates} extra ticket${data.total_duplicates !== 1 ? 's' : ''}
          </span>
          <div style="margin-top:4px;font-size:12px;color:var(--text-dim)">
            Tickets marked <strong>duplicate</strong> are the ones to close/delete in Jira.
          </div>
        </div>
        <div style="display:flex;gap:8px">
          <button class="btn btn-secondary" onclick="downloadDuplicatesExcel()" style="white-space:nowrap;background:var(--green);border-color:var(--green);color:white">
            📥 Export to Excel
          </button>
          <button class="btn btn-secondary" onclick="openAllKeeps()" style="white-space:nowrap">
            🔗 Open All ${k} Keep${k !== 1 ? '' : ''} (Old) in Jira
          </button>
          <button class="btn btn-primary" onclick="openAllDuplicates()" style="white-space:nowrap">
            🔗 Open All ${n} Duplicate${n !== 1 ? 's' : ''} in Jira
          </button>
        </div>
      </div>
      <div class="report-card" style="padding:14px;margin-bottom:0">
        <div style="font-size:12px;font-weight:600;color:var(--text);margin-bottom:10px">
          👤 Tester (duplicate tickets only)
        </div>
        <table style="border-collapse:collapse;width:100%;font-size:13px">
          ${reporterRows}
        </table>
      </div>
    </div>`;

  const groupsHtml = data.groups.map(g => {
    const ticketsHtml = g.tickets.map(t => {
      const isKeep = t.key === g.keep;
      return `
        <div class="dup-ticket-row ${isKeep ? 'dup-keep' : ''}">
          <a class="dup-key" href="${escHtml(t.jira_url)}" target="_blank" rel="noopener"
             title="Open in Jira">${escHtml(t.key)} ↗</a>
          <span class="dup-status">${escHtml(t.status || '—')}</span>
          ${(t.tester || t.reporter) ? `<span style="font-size:11px;color:var(--text-dim)">by ${escHtml(t.tester || t.reporter)}</span>` : ''}
          ${isKeep
            ? '<span class="dup-badge dup-badge-keep">keep</span>'
            : '<span class="dup-badge dup-badge-dup">duplicate</span>'}
        </div>`;
    }).join('');

    return `
      <div class="report-card dup-group" style="margin-bottom:16px">
        <div class="report-card-header">${escHtml(g.vuln_name)}</div>
        <div class="report-card-body" style="padding-top:10px">${ticketsHtml}</div>
      </div>`;
  }).join('');

  container.innerHTML = summary + groupsHtml;
}

function _jiraSearchUrl(tickets) {
  const firstUrl = tickets[0].url;
  const browseIdx = firstUrl.indexOf('/browse/');
  const baseUrl = browseIdx !== -1 ? firstUrl.substring(0, browseIdx) : firstUrl;
  const keys = tickets.map(d => d.key).join(', ');
  return `${baseUrl}/issues/?jql=${encodeURIComponent(`issueKey IN (${keys})`)}`;
}

function openAllDuplicates() {
  if (!_dupUrlsToClose.length) { showToast('No duplicates to open.', 'warn'); return; }
  window.open(_jiraSearchUrl(_dupUrlsToClose), '_blank', 'noopener');
  showToast(`Opened Jira filter for all ${_dupUrlsToClose.length} duplicate tickets.`, 'success');
}

function openAllKeeps() {
  if (!_keepUrls.length) { showToast('No keep tickets to open.', 'warn'); return; }
  window.open(_jiraSearchUrl(_keepUrls), '_blank', 'noopener');
  showToast(`Opened Jira filter for all ${_keepUrls.length} keep (old) tickets.`, 'success');
}

function openDuplicatesForTester(idx) {
  const entry = _dupTesterList[idx];
  if (!entry) { showToast('No tickets found.', 'warn'); return; }
  const [name, tickets] = entry;
  if (!tickets.length) { showToast('No tickets found for this tester.', 'warn'); return; }
  window.open(_jiraSearchUrl(tickets), '_blank', 'noopener');
  showToast(`Opened ${tickets.length} ticket${tickets.length !== 1 ? 's' : ''} for ${name}.`, 'success');
}

async function downloadDuplicatesExcel() {
  if (!_currentDuplicatesData) return;
  showToast('Generating Excel file...', 'info');
  try {
    const res = await fetch('/api/duplicates/export', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(_currentDuplicatesData)
    });
    if (!res.ok) throw new Error('Failed to generate Excel file');
    
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `duplicates_${_currentDuplicatesData.client}.xlsx`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    a.remove();
  } catch (e) {
    showToast(e.message, 'error');
  }
}

// ── Batch Scan ────────────────────────────────────────────────────────────
let _batchResults   = [];
let _batchRulesLoaded = false;
let _batchScanId    = null;   // active scan_id for streaming / cancel
let _batchTotal     = 0;
let _batchRuleName  = '';
let _batchHasCert   = false;

async function initBatchScan() {
  if (_batchRulesLoaded) return;
  try {
    const res   = await fetch('/api/batch-scan/rules');
    const rules = await res.json();
    const sel   = $('batchRule');
    sel.innerHTML = '<option value="">— Select a scan rule —</option>';
    rules.forEach(r => {
      const opt = document.createElement('option');
      opt.value = r.name;
      opt.textContent = r.name;
      sel.appendChild(opt);
    });
    _batchRulesLoaded = true;
  } catch (e) {
    console.warn('Could not load scan rules:', e);
    const sel = $('batchRule');
    if (sel) sel.innerHTML = '<option value="">Failed to load rules — retry</option>';
  }
}

async function runBatchScan() {
  const client   = $('batchClient').value;
  const ruleName = $('batchRule').value;
  const file     = $('batchFile').files[0];
  if (!client)   { showToast('Please select a client', 'warn');       return; }
  if (!ruleName) { showToast('Please select a scan rule', 'warn');    return; }
  if (!file)     { showToast('Please select an Excel or CSV file', 'warn'); return; }

  // ── Phase 1: POST to start scan, get scan_id + total ──────────────────
  const runBtn  = $('batchRunBtn');
  const stopBtn = $('batchStopBtn');
  runBtn.disabled   = true;
  runBtn.textContent = 'Starting…';
  stopBtn.style.display = '';
  $('batchProgress').style.display = '';
  $('batchProgressBar').style.width = '0%';
  $('batchProgressText').textContent = 'Starting scan…';
  $('batchResults').innerHTML = '';
  _batchResults  = [];
  _batchScanId   = null;

  let scanId, total;
  try {
    const form = new FormData();
    form.append('client',    client);
    form.append('rule_name', ruleName);
    form.append('file',      file);
    const res  = await fetch('/api/batch-scan/run', { method: 'POST', body: form });
    const data = await res.json();
    if (!res.ok) {
      $('batchProgress').style.display = 'none';
      stopBtn.style.display = 'none';
      $('batchResults').innerHTML = `<div class="report-error">⚠️ ${escHtml(data.detail || 'Unknown error')}</div>`;
      runBtn.disabled   = false;
      runBtn.textContent = 'Run Scan';
      return;
    }
    scanId         = data.scan_id;
    total          = data.total;
    _batchScanId   = scanId;
    _batchTotal    = total;
    _batchRuleName = data.rule;
  } catch (e) {
    $('batchProgress').style.display = 'none';
    stopBtn.style.display = 'none';
    $('batchResults').innerHTML = `<div class="report-error">⚠️ Request failed: ${escHtml(e.message)}</div>`;
    runBtn.disabled   = false;
    runBtn.textContent = 'Run Scan';
    return;
  }

  runBtn.textContent = `Scanning…`;

  // Seed the results table structure immediately
  _batchHasCert = false;
  _batchResults = [];
  $('batchResults').innerHTML = _batchTableShell(ruleName, total, false);

  // ── Phase 2: Stream results via SSE ────────────────────────────────────
  try {
    const resp   = await fetch(`/api/batch-scan/stream/${scanId}`);
    const reader = resp.body.getReader();
    const dec    = new TextDecoder();
    let   buf    = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      const lines = buf.split('\n');
      buf = lines.pop();

      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        let msg;
        try { msg = JSON.parse(line.slice(6)); } catch { continue; }

        if (msg.type === 'result') {
          const r = msg.data;
          _batchResults.push(r);

          // Detect cert columns on first cert-bearing row
          if (!_batchHasCert && r.valid_to && r.valid_to !== 'N/A') {
            _batchHasCert = true;
            // Rebuild table with cert headers
            $('batchResults').innerHTML = _batchTableShell(ruleName, total, true);
            // Re-append all previous rows
            const tbody = document.querySelector('#batchResults tbody');
            _batchResults.slice(0, -1).forEach(prev => {
              tbody.insertAdjacentHTML('beforeend', _batchRow(prev, true));
            });
          }

          // Append this row
          const tbody = document.querySelector('#batchResults tbody');
          if (tbody) tbody.insertAdjacentHTML('beforeend', _batchRow(r, _batchHasCert));

          // Update summary counters
          _batchUpdateCounts();

          // Progress bar
          const done_count = msg.done || _batchResults.length;
          const pct = Math.round((done_count / total) * 100);
          $('batchProgressBar').style.width = pct + '%';
          $('batchProgressText').textContent = `Scanning ${done_count} of ${total} assets…`;

        } else if (msg.type === 'done' || msg.type === 'cancelled') {
          const label = msg.type === 'cancelled' ? 'Scan stopped' : 'Scan complete';
          $('batchProgressText').textContent = `${label} — ${_batchResults.length} of ${total} assets`;
          $('batchProgressBar').style.width  = '100%';
          // Show export button in summary
          const expBtn = document.getElementById('batchExportBtn');
          if (expBtn) expBtn.style.display = '';
          break;
        }
      }
    }
  } catch (e) {
    if (_batchScanId) {  // not a user cancel
      $('batchResults').insertAdjacentHTML('beforeend',
        `<div class="report-error" style="margin-top:8px">⚠️ Stream error: ${escHtml(e.message)}</div>`);
    }
  } finally {
    _batchScanId = null;
    runBtn.disabled    = false;
    runBtn.textContent = 'Run Scan';
    stopBtn.style.display = 'none';
    if (_batchResults.length) $('batchClearBtn').style.display = '';
  }
}

async function stopBatchScan() {
  if (!_batchScanId) return;
  const id = _batchScanId;
  _batchScanId = null;   // prevent error toast in catch block above
  try {
    await fetch(`/api/batch-scan/cancel/${id}`, { method: 'POST' });
  } catch { /* ignore */ }
  showToast('Scan stopped', 'warn');
}

function clearBatchScan() {
  _batchResults  = [];
  _batchScanId   = null;
  _batchTotal    = 0;
  _batchRuleName = '';
  _batchHasCert  = false;
  $('batchResults').innerHTML   = '';
  $('batchProgress').style.display  = 'none';
  $('batchProgressBar').style.width = '0%';
  $('batchClearBtn').style.display  = 'none';
  $('batchFile').value = '';
}

// Build the empty table shell (summary row + table headers + empty tbody)
function _batchTableShell(ruleName, total, hasCert) {
  const certHdr = hasCert ? '<th>Valid To</th><th>Days</th>' : '';
  return `
    <div style="margin-bottom:12px">
      <div style="font-size:14px;font-weight:700;color:var(--text);margin-bottom:8px">
        ${escHtml(ruleName)} — ${total} assets
      </div>
      <div id="batchCounts" style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
        <span class="ssl-badge ssl-valid"  id="bc-fixed">✅ 0 Not Vulnerable</span>
        <span class="ssl-badge ssl-expired" id="bc-notfixed">❌ 0 Vulnerable</span>
        <span class="ssl-badge ssl-nocert" id="bc-inconclusive">⚠️ 0 Inconclusive</span>
        <button id="batchExportBtn" class="btn btn-secondary btn-sm" onclick="exportBatchCsv()"
                style="margin-left:auto;display:none">⬇ Export CSV</button>
      </div>
    </div>
    <div class="report-vuln-card">
      <table class="report-vuln-table">
        <thead><tr><th>IP</th><th>Port</th>${certHdr}<th>Status</th><th>Detail</th></tr></thead>
        <tbody></tbody>
      </table>
    </div>`;
}

function _batchRow(r, hasCert) {
  const cls  = { fixed: 'ssl-valid', not_fixed: 'ssl-expired', inconclusive: 'ssl-nocert' }[r.verdict] || 'ssl-nocert';
  const days = typeof r.days === 'number'
    ? (r.days < 0 ? `<span style="color:var(--red)">${r.days}</span>` : r.days)
    : escHtml(String(r.days));
  const certCols = hasCert
    ? `<td>${escHtml(r.valid_to)}</td><td>${days}</td>`
    : '';
  return `<tr>
    <td>${escHtml(r.ip)}</td>
    <td>${escHtml(String(r.port))}</td>
    ${certCols}
    <td><span class="ssl-status-badge ${cls}">${escHtml(r.status)}</span></td>
    <td style="font-size:11px;color:var(--text-dim)">${escHtml(r.detail)}</td>
  </tr>`;
}

function _batchUpdateCounts() {
  const counts = { fixed: 0, not_fixed: 0, inconclusive: 0 };
  _batchResults.forEach(r => {
    const k = r.verdict;
    if (k in counts) counts[k]++; else counts.inconclusive++;
  });
  const f = document.getElementById('bc-fixed');
  const n = document.getElementById('bc-notfixed');
  const i = document.getElementById('bc-inconclusive');
  if (f) f.textContent = `✅ ${counts.fixed} Not Vulnerable`;
  if (n) n.textContent = `❌ ${counts.not_fixed} Vulnerable`;
  if (i) i.textContent = `⚠️ ${counts.inconclusive} Inconclusive`;
}

async function exportBatchCsv() {
  if (!_batchResults.length) { showToast('No results to export', 'warn'); return; }
  try {
    const rule = _batchRuleName || $('batchRule').value;
    const res  = await fetch('/api/batch-scan/export', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ results: _batchResults, rule }),
    });
    if (!res.ok) { showToast('Export failed', 'error'); return; }
    const blob = await res.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url;
    a.download = res.headers.get('Content-Disposition')?.match(/filename=(.+)/)?.[1] || 'batch_scan.csv';
    a.click();
    URL.revokeObjectURL(url);
  } catch (e) {
    showToast(`Export failed: ${e.message}`, 'error');
  }
}

// ── Theme ─────────────────────────────────────────────────────────────────
function toggleTheme() {
  const isLight = document.documentElement.getAttribute('data-theme') === 'light';
  const next = isLight ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', next);
  $('themeBtn').textContent = next === 'light' ? '🌙' : '☀️';
  localStorage.setItem('theme', next);
}

// ── Keyboard shortcuts ─────────────────────────────────────────────────────
document.addEventListener('keydown', e => {
  if (e.key !== 'Escape') return;
  if ($('addTicketModal')?.style.display !== 'none')      { closeAddTicket(); return; }
  if ($('sweepModal')?.style.display !== 'none')          { closeSweep(); return; }
  if ($('bulkTransitionModal')?.style.display !== 'none') { closeTransitionModal(); return; }
  if ($('triageTransitionModal')?.style.display !== 'none') { closeTriageTransitionModal(); return; }
  if ($('transitionModal')?.style.display !== 'none')     { _closeTransitionModal(); }
});

// ── Shell Tab ─────────────────────────────────────────────────────────────
// Real interactive bash session on a client's Kali box, via xterm.js over a
// WebSocket — typed keystrokes go straight to the remote PTY, raw output
// comes straight back, just like a normal terminal.
let _shellTerm = null;
let _shellFit = null;
let _shellSocket = null;
let _shellResizeListenerAdded = false;
let _shellResizeObserver = null;
let _shellFitDebounce = null;
let _shellLastSent = { cols: 0, rows: 0 };   // last dims sent to the PTY

function _shellViewVisible() {
  const v = $('shellView');
  return v && v.style.display !== 'none';
}

// Fit the terminal to its container and, only when the size actually changed,
// tell the remote PTY. Sending a resize on every call made bash reprint its
// prompt over and over (the stacked blank prompts). Returns true once a real
// fit has been applied (renderer ready), false to request a retry.
function _shellFitAndSync() {
  if (!_shellTerm || !_shellFit || !_shellViewVisible()) return false;
  const el = $('shellTerminalContainer');
  if (!el || el.clientWidth < 20 || el.clientHeight < 20) return false;

  // FitAddon.proposeDimensions() returns undefined/NaN until xterm has painted
  // (cell size still 0). Don't let fit() silently no-op — signal a retry.
  let dims;
  try { dims = _shellFit.proposeDimensions(); } catch (e) { dims = null; }
  if (!dims || !dims.rows || !dims.cols || isNaN(dims.rows) || isNaN(dims.cols)) {
    return false;
  }

  try { _shellFit.fit(); } catch (e) { return false; }

  const cols = _shellTerm.cols, rows = _shellTerm.rows;
  if (_shellSocket && _shellSocket.readyState === WebSocket.OPEN
      && (cols !== _shellLastSent.cols || rows !== _shellLastSent.rows)) {
    _shellSocket.send(JSON.stringify({ type: 'resize', cols, rows }));
    _shellLastSent = { cols, rows };
  }
  try { _shellTerm.scrollToBottom(); } catch (e) { /* older xterm */ }
  return true;
}

// Retry until the renderer is ready (cell dims known) so the terminal never
// gets stuck at the default 80x24 on a small viewport.
function _shellFitRetry(attempts = 15) {
  if (_shellFitAndSync()) return;
  if (attempts <= 0) return;
  setTimeout(() => requestAnimationFrame(() => _shellFitRetry(attempts - 1)), 50);
}

// Debounced so a burst of resize/observer events collapses into one fit —
// prevents the fit→resize→observer feedback loop that stacked prompts.
function _scheduleShellFit() {
  if (_shellFitDebounce) clearTimeout(_shellFitDebounce);
  _shellFitDebounce = setTimeout(() => requestAnimationFrame(() => _shellFitRetry()), 120);
}

function initShellTab() {
  // Options are kept in sync by _syncClientDropdowns() via fetchClients().

  if (!_shellTerm) {
    _shellTerm = new Terminal({
      cursorBlink: true,
      fontSize: 13,
      fontFamily: 'Menlo, Consolas, "DejaVu Sans Mono", monospace',
      theme: { background: '#0d1117', foreground: '#e6edf3' },
      scrollback: 10000,
      scrollOnUserInput: true,
    });
    _shellFit = new FitAddon.FitAddon();
    _shellTerm.loadAddon(_shellFit);
    _shellTerm.open($('shellTerminalContainer'));

    _shellTerm.onData((data) => {
      if (_shellSocket && _shellSocket.readyState === WebSocket.OPEN) {
        _shellSocket.send(JSON.stringify({ type: 'input', data }));
      }
    });

    if (!_shellResizeListenerAdded) {
      window.addEventListener('resize', _scheduleShellFit);
      _shellResizeListenerAdded = true;
    }
    // Observe the OUTER card, not the terminal container: FitAddon resizes the
    // .xterm element inside the container, so observing the container itself
    // would re-trigger on our own fit and loop. The card has a fixed height, so
    // it only changes when the window/layout genuinely changes.
    if (window.ResizeObserver && !_shellResizeObserver) {
      const card = document.querySelector('.shell-terminal-card');
      if (card) {
        _shellResizeObserver = new ResizeObserver(_scheduleShellFit);
        _shellResizeObserver.observe(card);
      }
    }
  }

  // The container just became visible on tab switch; fit once layout settles.
  _scheduleShellFit();
  startTunnelPolling();
}

function _setShellConnectedUi(connected) {
  $('shellConnectBtn').style.display = connected ? 'none' : '';
  $('shellDisconnectBtn').style.display = connected ? '' : 'none';
}

function connectShell() {
  const label = $('shellClient').value;
  const status = $('shellStatus');
  if (!label) { status.textContent = 'Select a client first.'; return; }

  if (_shellSocket) {
    _shellSocket.onclose = null;
    _shellSocket.close();
    _shellSocket = null;
  }

  _shellTerm.reset();
  _shellLastSent = { cols: 0, rows: 0 };  // force a resize send on this session
  status.textContent = `Connecting to ${label}…`;

  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(`${proto}//${location.host}/ws/shell/${encodeURIComponent(label)}`);
  _shellSocket = ws;

  ws.onopen = () => {
    // Fit first (retrying until the renderer is ready) so the PTY starts at the
    // correct dims and the prompt isn't rendered below the visible area.
    _shellFitRetry();
    status.textContent = `Connected to ${label}`;
    _setShellConnectedUi(true);
    _shellTerm.focus();
  };

  ws.onmessage = (e) => {
    let msg;
    try { msg = JSON.parse(e.data); } catch { return; }
    if (msg.type === 'output') {
      // write() is async in newer xterm — scroll after the buffer settles so
      // large dumps (e.g. `history`) leave the prompt visible, not clipped.
      _shellTerm.write(msg.data, () => {
        try { _shellTerm.scrollToBottom(); } catch (err) { /* ignore */ }
      });
    } else if (msg.type === 'error') {
      _shellTerm.write(`\r\n\x1b[31m[ERROR] ${msg.data}\x1b[0m\r\n`);
      status.textContent = 'Error';
      _setShellConnectedUi(false);
    } else if (msg.type === 'closed') {
      _shellTerm.write('\r\n\x1b[2m[session closed]\x1b[0m\r\n');
      status.textContent = 'Disconnected';
      _setShellConnectedUi(false);
    }
  };

  ws.onclose = () => {
    if (_shellSocket === ws) {
      _shellSocket = null;
      status.textContent = 'Disconnected';
      _setShellConnectedUi(false);
    }
  };

  ws.onerror = () => {
    status.textContent = 'Connection error';
  };
}

function disconnectShell() {
  if (_shellSocket) {
    _shellSocket.onclose = null;
    _shellSocket.close();
    _shellSocket = null;
  }
  $('shellStatus').textContent = 'Disconnected';
  _setShellConnectedUi(false);
}

// ── Port Forward (Tunnels) ───────────────────────────────────────────────
let _tunnelPollTimer = null;

function startTunnelPolling() {
  if (_tunnelPollTimer) return;
  refreshTunnels();
  _tunnelPollTimer = setInterval(refreshTunnels, 2000);
}

function stopTunnelPolling() {
  if (_tunnelPollTimer) {
    clearInterval(_tunnelPollTimer);
    _tunnelPollTimer = null;
  }
}

async function startTunnel(ev) {
  if (ev) {
    ev.preventDefault();
    ev.stopPropagation();
  }

  const label = $('shellClient').value;
  const target = $('tunnelTarget').value.trim();
  const localPortRaw = $('tunnelLocalPort').value.trim();

  if (!label) { showToast('Select a client first', 'warn'); return; }
  const m = target.match(/^([^:\s]+):(\d+)$/);
  if (!m) { showToast('Target must be host:port, e.g. 127.0.0.1:8080', 'warn'); return; }

  // Left blank → default to the same port locally, so pasting just
  // "host:port" into the target field is enough to start a tunnel.
  const localPort = localPortRaw ? parseInt(localPortRaw, 10) : parseInt(m[2], 10);
  if (!localPort || localPort < 1 || localPort > 65535) { showToast('Enter a valid local port (1–65535)', 'warn'); return; }

  const btn = document.querySelector('.pf-start-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Starting…'; }
  try {
    const resp = await fetch('/api/tunnels', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        label,
        target_host: m[1],
        target_port: parseInt(m[2], 10),
        local_port: localPort,
      }),
    });
    const data = await resp.json();
    if (!resp.ok) { showToast(data.detail || 'Failed to start tunnel', 'error'); return; }
    $('tunnelTarget').value = '';
    $('tunnelLocalPort').value = '';
    showToast(`Tunnel started on localhost:${localPort}`, 'success');
    refreshTunnels();
  } catch (exc) {
    showToast(`Error: ${exc.message || exc}`, 'error');
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = '▶ Start Tunnel';
      btn.blur();
    }
  }
}

async function stopTunnel(tunnelId) {
  try {
    await fetch(`/api/tunnels/${tunnelId}`, { method: 'DELETE' });
  } catch (exc) { /* ignore */ }
  refreshTunnels();
}

let _lastTunnelSig = null;
async function refreshTunnels() {
  let tunnels;
  try {
    const resp = await fetch('/api/tunnels');
    if (!resp.ok) return;
    tunnels = await resp.json();
  } catch (exc) {
    return;
  }

  const list = $('tunnelList');
  if (!list) return;

  const prevScroll = list.scrollTop;

  // Only touch the DOM when something actually changed — avoids the 2s poll
  // wiping the list mid-click and causing flicker.
  const sig = JSON.stringify(tunnels.map(t =>
    [t.id, t.status, t.local_port, t.target_host, t.target_port, t.error || '']));
  if (sig === _lastTunnelSig) return;
  _lastTunnelSig = sig;

  if (!tunnels.length) {
    list.innerHTML = '<div class="pf-empty">No active tunnels.</div>';
    list.scrollTop = prevScroll;
    return;
  }

  // Map every backend status to a visual class + label. The backend uses
  // "connecting" while the double-hop SSH is being established.
  const statusMap = {
    listening:  { cls: 'listening', text: 'Listening' },
    error:      { cls: 'error',     text: 'Error' },
    connecting: { cls: 'starting',  text: 'Connecting' },
    starting:   { cls: 'starting',  text: 'Starting' },
    stopped:    { cls: 'stopped',   text: 'Stopped' },
  };
  list.innerHTML = tunnels.map((t) => {
    const raw = t.status || 'connecting';
    const info = statusMap[raw] || { cls: 'starting', text: raw };
    const openBtn = raw === 'listening'
      ? `<a href="http://localhost:${encodeURIComponent(t.local_port)}" target="_blank" rel="noopener" class="btn btn-secondary btn-sm">↗ Open</a>`
      : '';
    const errorSpan = t.error
      ? `<span class="tunnel-error" title="${escHtml(t.error)}">${escHtml(t.error)}</span>`
      : '';
    return `
      <div class="tunnel-row tunnel-${info.cls}">
        <span class="tunnel-dot"></span>
        <span class="tunnel-status">${escHtml(info.text)}</span>
        <span class="tunnel-label">${escHtml(t.label)}</span>
        <span class="tunnel-route">
          <code>localhost:${escHtml(t.local_port)}</code>
          <span class="tunnel-arrow">→</span>
          <code>${escHtml(t.target_host)}:${escHtml(t.target_port)}</code>
        </span>
        ${errorSpan}
        <span class="tunnel-actions">
          ${openBtn}
          <button class="btn btn-red btn-sm" onclick="stopTunnel('${escHtml(t.id)}')">⏹ Stop</button>
        </span>
      </div>`;
  }).join('');
  list.scrollTop = prevScroll;
}

// ── Settings Tab ──────────────────────────────────────────────────────────
let _settingsLoaded = false;
let _settingsRowSeq = 0;

function settingsClientRowHtml(c, session = 'axian') {
  const rowId = `set-client-${_settingsRowSeq++}`;
  const labelLocked = !!c.label;
  return `
    <div class="settings-client-row" id="${rowId}" data-orig-label="${escHtml(c.label || '')}" data-session="${session}">
      <button type="button" class="settings-remove-client" onclick="removeSettingsClientRow('${rowId}')" title="Remove client">✕</button>
      <div class="settings-client-row-grid">
        <div>
          <label>Label${session === 'non_axian' ? ' (= project key)' : ''}</label>
          <input type="text" class="text-input set-c-label" value="${escHtml(c.label || '')}" ${labelLocked ? 'readonly' : ''} placeholder="${session === 'non_axian' ? 'CPEL' : 'ClientA'}">
        </div>
        <div>
          <label>Display Name</label>
          <input type="text" class="text-input set-c-name" value="${escHtml(c.name || '')}" placeholder="${session === 'non_axian' ? 'CPEL Project' : 'Client A'}">
        </div>
        <div>
          <label>Kali Port</label>
          <input type="number" class="text-input set-c-kaliport" value="${c.kali_port || 22}">
        </div>
        <div>
          <label>Kali User</label>
          <input type="text" class="text-input set-c-kaliuser" value="${escHtml(c.kali_user || 'kali')}">
        </div>
      </div>
      <div class="settings-client-row-grid2">
        <div>
          <label>Kali Password ${c.kali_password_set ? '<span style="color:var(--green)">(set)</span>' : '<span style="color:var(--orange)">(not set)</span>'}</label>
          <input type="password" class="text-input set-c-kalipass" placeholder="Leave blank to keep current">
        </div>
        <div>
          <label>Nessus Access Key ${c.nessus_access_key_set ? '<span style="color:var(--green)">(set)</span>' : '<span style="color:var(--text-dim)">(not set)</span>'}</label>
          <input type="password" class="text-input set-c-nessusaccess" placeholder="Leave blank to keep current">
        </div>
        <div>
          <label>Nessus Secret Key ${c.nessus_secret_key_set ? '<span style="color:var(--green)">(set)</span>' : '<span style="color:var(--text-dim)">(not set)</span>'}</label>
          <input type="password" class="text-input set-c-nessussecret" placeholder="Leave blank to keep current">
        </div>
      </div>

      <!-- Nessus fetch-keys helper (collapsed by default) -->
      <div class="set-c-fetchkeys-wrap" style="margin-top:10px;border-top:1px solid var(--border);padding-top:10px">
        <button type="button" class="btn btn-sm btn-secondary set-c-fetchkeys-toggle"
                onclick="toggleNessusFetchKeys('${rowId}')"
                style="font-size:11px">
          🔑 Auto-fetch Nessus Keys
        </button>
        <div id="${rowId}-fetchkeys" style="display:none;margin-top:10px">
          <div style="font-size:11px;color:var(--text-dim);margin-bottom:8px">
            Enter your Nessus credentials — the app will log in via SSH and generate a new key pair automatically.
            <strong>SSH must be connected for this client first.</strong>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr auto;gap:8px;align-items:flex-end">
            <div>
              <label style="font-size:11px">Nessus Username</label>
              <input type="text" class="text-input set-c-nessususer" placeholder="admin" autocomplete="off"
                     style="font-size:12px;padding:6px 8px">
            </div>
            <div>
              <label style="font-size:11px">Nessus Password</label>
              <input type="password" class="text-input set-c-nessuspass" placeholder="••••••••"
                     style="font-size:12px;padding:6px 8px">
            </div>
            <button type="button" class="btn btn-primary btn-sm set-c-fetchkeys-btn"
                    onclick="fetchNessusKeys('${rowId}')"
                    style="font-size:11px;white-space:nowrap">
              Fetch Keys
            </button>
          </div>
          <div class="set-c-fetchkeys-status" style="font-size:11px;margin-top:6px;display:none"></div>
        </div>
      </div>
    </div>
  `;
}

function toggleNessusFetchKeys(rowId) {
  const panel = document.getElementById(rowId + '-fetchkeys');
  if (!panel) return;
  const hidden = panel.style.display === 'none';
  panel.style.display = hidden ? '' : 'none';
  const row = document.getElementById(rowId);
  if (!row) return;
  const btn = row.querySelector('.set-c-fetchkeys-toggle');
  if (btn) btn.textContent = hidden ? '🔑 Hide Nessus Key Fetch' : '🔑 Auto-fetch Nessus Keys';
}

async function fetchNessusKeys(rowId) {
  const row = document.getElementById(rowId);
  if (!row) return;

  const label   = row.querySelector('.set-c-label')?.value?.trim();
  const user    = row.querySelector('.set-c-nessususer')?.value?.trim();
  const pass    = row.querySelector('.set-c-nessuspass')?.value;
  const statusEl = row.querySelector('.set-c-fetchkeys-status');
  const btn      = row.querySelector('.set-c-fetchkeys-btn');

  if (!label) { showToast('Save settings with a client label first, then retry.', 'warn'); return; }
  if (!user)  { showToast('Enter the Nessus username.', 'warn'); return; }
  if (!pass)  { showToast('Enter the Nessus password.', 'warn'); return; }

  const setStatus = (msg, color) => {
    if (!statusEl) return;
    statusEl.style.display = '';
    statusEl.style.color = color || 'var(--text-dim)';
    statusEl.textContent = msg;
  };

  btn.disabled = true;
  btn.textContent = 'Fetching…';
  setStatus('Connecting to Nessus via SSH…', 'var(--text-dim)');

  try {
    const res = await fetch(`/api/nessus/${encodeURIComponent(label)}/fetch-keys`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: user, password: pass }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Key fetch failed');

    // Fill in the key inputs
    const accInput = row.querySelector('.set-c-nessusaccess');
    const secInput = row.querySelector('.set-c-nessussecret');
    if (accInput) accInput.value = data.access_key;
    if (secInput) secInput.value = data.secret_key;

    setStatus('✅ Keys fetched — click Save Settings to persist them.', 'var(--green)');
    showToast('Nessus keys fetched — save settings to apply.', 'success');

    // Clear the credentials from the form
    row.querySelector('.set-c-nessususer').value = '';
    row.querySelector('.set-c-nessuspass').value = '';
  } catch (exc) {
    setStatus(`❌ ${exc.message}`, 'var(--red)');
    showToast(exc.message, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Fetch Keys';
  }
}

function renderSettings(data) {
  $('setJiraUrl').value           = data.jira.url;
  $('setJiraUsername').value      = data.jira.username;
  $('setJiraProject').value       = data.jira.project;
  $('setJiraRetestStatus').value  = data.jira.retest_status;
  $('setJiraPollInterval').value  = data.jira.poll_interval;
  $('setJiraToken').value         = '';
  $('setJiraTokenStatus').innerHTML = data.jira.api_token_set
    ? '<span style="color:var(--green)">(set — leave blank to keep)</span>'
    : '<span style="color:var(--orange)">(not set)</span>';

  // Non-Axian Jira
  const j2 = data.jira_secondary || {};
  $('setJira2Url').value          = j2.url || '';
  $('setJira2RetestStatus').value = j2.retest_status || 'Remediated';
  $('setJira2PollInterval').value = j2.poll_interval || 300;
  $('setJira2Token').value        = '';
  $('setJira2TokenStatus').innerHTML = j2.api_token_set
    ? '<span style="color:var(--green)">(set — leave blank to keep)</span>'
    : '<span style="color:var(--text-dim)">(not set)</span>';

  $('setJumpHost').value     = data.jump_server.host;
  $('setJumpPort').value     = data.jump_server.port;
  $('setJumpUser').value     = data.jump_server.user;
  $('setJumpPassword').value = '';
  $('setJumpPasswordStatus').innerHTML = data.jump_server.password_set
    ? '<span style="color:var(--green)">(set — leave blank to keep)</span>'
    : '<span style="color:var(--orange)">(not set)</span>';

  $('settingsClientRows').innerHTML = (data.clients || []).map(c => settingsClientRowHtml(c, 'axian')).join('')
    || '<span style="color:var(--text-dim);font-size:12px">No clients configured yet — click "+ Add Client".</span>';

  $('settingsClientRowsSecondary').innerHTML = (data.clients_secondary || []).map(c => settingsClientRowHtml(c, 'non_axian')).join('')
    || '<div style="font-size:11px;color:var(--text-dim);padding:4px 0">No Non-Axian clients yet — click "+ Add Client" to add one.</div>';
}

async function initSettingsTab() {
  if (_settingsLoaded) return;
  _settingsLoaded = true;
  try {
    const res = await fetch('/api/settings');
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Failed to load settings');
    renderSettings(data);
  } catch (exc) {
    $('settingsClientRows').innerHTML = '';
    showToast(exc.message, 'error');
    _settingsLoaded = false;
  }
}

function addSettingsClientRow() {
  $('settingsClientRows').insertAdjacentHTML('beforeend', settingsClientRowHtml({}, 'axian'));
}

function addSecondaryClientRow() {
  const container = $('settingsClientRowsSecondary');
  // Remove only the "no clients yet" placeholder — anything that isn't a real
  // client row. Re-serializing innerHTML (the old approach) discarded every
  // value the user had already typed into existing rows, since input values
  // don't round-trip through .innerHTML.
  Array.from(container.children).forEach((child) => {
    if (!child.classList || !child.classList.contains('settings-client-row')) {
      child.remove();
    }
  });
  container.insertAdjacentHTML('beforeend', settingsClientRowHtml({}, 'non_axian'));
}

function removeSettingsClientRow(rowId) {
  const row = $(rowId);
  if (!row) return;
  const label = row.dataset.origLabel;
  if (label && !confirm(`Remove client "${label}" from config.yaml? This cannot be undone.`)) return;
  row.remove();
}

// ── Session switcher ──────────────────────────────────────────────────────

async function initSessionBar() {
  try {
    const res = await fetch('/api/session');
    if (!res.ok) return;
    const data = await res.json();
    _applySessionUI(data.active, data.non_axian_configured);
  } catch (e) { /* ignore */ }
}

function _applySessionUI(session, nonAxianConfigured) {
  const btnA = $('btnSessionAxian');
  const btnB = $('btnSessionNonAxian');
  const lbl  = $('sessionActiveLabel');
  if (!btnA || !btnB) return;
  btnA.classList.toggle('active', session === 'axian');
  btnB.classList.toggle('active', session === 'non_axian');
  btnB.disabled = !nonAxianConfigured;
  btnB.title = nonAxianConfigured ? '' : 'Configure Non-Axian Jira in Settings first';
  lbl.textContent = session === 'axian' ? 'Axian Jira' : 'Non-Axian Jira';
  lbl.style.color = session === 'non_axian' ? 'var(--blue)' : 'var(--text-dim)';
}

async function switchSession(session) {
  try {
    const res = await fetch('/api/session', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session }),
    });
    const data = await res.json();
    if (!res.ok) {
      showToast(data.detail || 'Failed to switch session', 'error');
      return;
    }
    _applySessionUI(session, true);
    // Refresh everything for the new session
    await fetchClients();
    await fetchSshStatus();
    await fetchJobs();
    await fetchConfig();
    showToast(
      session === 'axian' ? 'Switched to Axian Jira' : 'Switched to Non-Axian Jira',
      'success', 3000
    );
  } catch (e) {
    showToast('Failed to switch session', 'error');
  }
}

async function saveSettings() {
  const clientRows = Array.from(document.querySelectorAll('.settings-client-row[data-session="axian"]'));
  const clients = clientRows.map(row => {
    const v = sel => row.querySelector(sel).value;
    return {
      label: v('.set-c-label').trim(),
      name: v('.set-c-name').trim(),
      kali_port: parseInt(v('.set-c-kaliport'), 10) || 22,
      kali_user: v('.set-c-kaliuser').trim() || 'kali',
      kali_password: v('.set-c-kalipass') || null,
      nessus_access_key: v('.set-c-nessusaccess') || null,
      nessus_secret_key: v('.set-c-nessussecret') || null,
    };
  });

  const secondaryRows = Array.from(document.querySelectorAll('.settings-client-row[data-session="non_axian"]'));
  const clients_secondary = secondaryRows.map(row => {
    const v = sel => row.querySelector(sel).value;
    return {
      label: v('.set-c-label').trim(),
      name: v('.set-c-name').trim(),
      kali_port: parseInt(v('.set-c-kaliport'), 10) || 22,
      kali_user: v('.set-c-kaliuser').trim() || 'kali',
      kali_password: v('.set-c-kalipass') || null,
      nessus_access_key: v('.set-c-nessusaccess') || null,
      nessus_secret_key: v('.set-c-nessussecret') || null,
    };
  });

  if (!clients.length) {
    showToast('Add at least one Axian client before saving.', 'error');
    return;
  }
  if (clients.some(c => !c.label)) {
    showToast('Every Axian client needs a label.', 'error');
    return;
  }
  if (clients_secondary.some(c => !c.label)) {
    showToast('Every Non-Axian client needs a label.', 'error');
    return;
  }

  const j2Url = $('setJira2Url').value.trim();
  const body = {
    jira: {
      url: $('setJiraUrl').value.trim(),
      username: $('setJiraUsername').value.trim(),
      api_token: $('setJiraToken').value || null,
      project: $('setJiraProject').value.trim(),
      retest_status: $('setJiraRetestStatus').value.trim() || 'Remediated',
      poll_interval: parseInt($('setJiraPollInterval').value, 10) || 300,
    },
    jira_secondary: j2Url ? {
      url: j2Url,
      api_token: $('setJira2Token').value || null,
      retest_status: $('setJira2RetestStatus').value.trim() || 'Remediated',
      poll_interval: parseInt($('setJira2PollInterval').value, 10) || 300,
    } : null,
    jump_server: {
      host: $('setJumpHost').value.trim(),
      port: parseInt($('setJumpPort').value, 10) || 22,
      user: $('setJumpUser').value.trim(),
      password: $('setJumpPassword').value || null,
    },
    clients,
    clients_secondary,
  };

  const btn = $('settingsSaveBtn');
  btn.disabled = true;
  btn.textContent = 'Validating…';
  $('settingsSaveStatus').textContent = 'Checking Jira and jump-server credentials…';

  try {
    const res = await fetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Failed to save settings');

    $('settingsSaveStatus').textContent = data.message;
    showToast(data.message, 'success', 8000);
    _settingsLoaded = false; // force a fresh reload (clears "(set)" state, picks up new rows) next visit
  } catch (exc) {
    $('settingsSaveStatus').textContent = '';
    showToast(exc.message, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Save Settings';
  }
}

// ── Boot ──────────────────────────────────────────────────────────────────
(async function init() {
  // Restore saved theme preference
  const saved = localStorage.getItem('theme');
  if (saved === 'light') {
    document.documentElement.setAttribute('data-theme', 'light');
    $('themeBtn').textContent = '☀️';
  }

  await initSessionBar();
  await fetchConfig();
  await fetchClients();
  await fetchJobs();
  await fetchLogs();
  await fetchSshStatus();

  // Poll jobs every 5s, SSH status every 3s, logs every 15s.
  // Skip work while the tab is backgrounded (document.hidden) so we don't burn
  // CPU/network re-rendering panels the user can't see; refresh immediately when
  // the tab becomes visible again so data is never stale on return.
  const pollGuarded = (fn) => () => { if (!document.hidden) fn(); };
  setInterval(pollGuarded(fetchJobs),      5_000);
  setInterval(pollGuarded(fetchSshStatus), 3_000);
  setInterval(pollGuarded(fetchLogs),     15_000);
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) { fetchJobs(); fetchSshStatus(); fetchLogs(); }
  });
})();

// ── Nemesis terminal prompt (top-left) ───────────────────────────────────
(function initNemesisTerminal() {
  const cmdEl = document.getElementById('nemesisCmd');
  if (!cmdEl) return;

  const commands = [
    { text: 'cd NEMESIS', pause: 2000, type: 55, del: 25 },
    { text: 'jira → scan → verdict → done', pause: 2600, type: 50, del: 22 },
    { text: 'no ssh. no copy-paste. no stress.', pause: 2800, type: 48, del: 22 },
    { text: 'manual retests → deleted', pause: 2400, type: 52, del: 24 },
    { text: 'sit back. nemesis handles it ✓', pause: 2600, type: 50, del: 22 },
    { text: '100+ rules · zero hand-holding', pause: 2600, type: 50, del: 22 },
    { text: 'automation beats burnout', pause: 2200, type: 55, del: 26, flex: true },
    { text: 'your job: click. mine: everything else.', pause: 2800, type: 45, del: 20, flex: true },
    { text: 'sudo rm -rf manual-labour', pause: 2400, type: 52, del: 24, flex: true },
  ];

  let cmdIdx = 0;
  let charIdx = 0;
  let deleting = false;

  function escapeHtml(str) {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function renderCmd(text, isFlex) {
    let html = escapeHtml(text)
      .replace(/NEMESIS/g, '<span class="nemesis-brand">NEMESIS</span>')
      .replace(/→/g, '<span class="nemesis-arrow">→</span>')
      .replace(/✓/g, '<span class="nemesis-ok">✓</span>');
    if (isFlex) html = `<span class="nemesis-flex">${html}</span>`;
    cmdEl.innerHTML = html;
  }

  function tick() {
    const entry = commands[cmdIdx];
    const current = entry.text;

    if (!deleting) {
      renderCmd(current.substring(0, charIdx + 1), entry.flex);
      charIdx++;
      if (charIdx >= current.length) {
        setTimeout(() => { deleting = true; tick(); }, entry.pause);
        return;
      }
      setTimeout(tick, entry.type);
    } else {
      renderCmd(current.substring(0, charIdx - 1), entry.flex);
      charIdx--;
      if (charIdx <= 0) {
        deleting = false;
        cmdIdx = (cmdIdx + 1) % commands.length;
        setTimeout(tick, 500);
        return;
      }
      setTimeout(tick, entry.del);
    }
  }

  tick();
})();
