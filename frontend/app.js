'use strict';

// ── State ─────────────────────────────────────────────────────────────────
const state = {
  jobs: {},           // jobId → job object
  selectedJobId: null,
  clientFilter: '',
  statusFilter: '',
  triageFilter: '',
  sweepSearch: '',
  sweepRenderLimit: 100, // grows as the user scrolls — see _sweepObserver
  checkedIds: new Set(),
  activeStreams: {},  // jobId → EventSource
};

// ── DOM refs ──────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

// Retest status from config — used to know which not_fixed jobs can transition
let _retestStatus = '';

// Bulk scan tracking — set while a Scan All batch is in progress, null otherwise
let _bulkScan = null; // { total: int, ids: Set<string> }

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
    // Re-attach stream for the selected job if it dropped (e.g. server restart)
    const _selJob = state.selectedJobId && newJobs[state.selectedJobId];
    if (_selJob && _selJob.status === 'scanning' && !state.activeStreams[_selJob.id]) {
      openStream(_selJob.id);
    }
  } catch (e) { /* network error, ignore */ }
}

async function fetchClients() {
  try {
    const res = await fetch('/api/clients');
    const clients = await res.json();
    const sel = $('clientFilter');
    clients.forEach(c => {
      const opt = document.createElement('option');
      opt.value = c.label;
      opt.textContent = `${c.name} (${c.label})`;
      sel.appendChild(opt);
    });
  } catch (e) { /* ignore */ }
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
             ${j.status === 'queued' ? '' : 'disabled'}>
      <div class="job-item-body">
        <div class="job-key">
          ${escHtml(j.ticket_key)}
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

  const remJobs   = jobs.filter(j => j.source !== 'sweep');
  const sweepJobs = jobs.filter(j => j.source === 'sweep');

  if (!jobs.length) {
    list.innerHTML = `<div style="padding:24px;text-align:center;color:var(--text-dim);font-size:12px;">
      No tickets found.<br>Waiting for Jira poll…
    </div>`;
    updateScanSelectedBtn();
    return;
  }

  let html = '';
  if (remJobs.length) {
    html += `<div class="queue-section-header">📋 REMEDIATED <span class="section-count">${remJobs.length}</span></div>`;
    html += remJobs.map(renderJobCard).join('');
  }
  let hasMoreSweep = false;
  if (sweepJobs.length) {
    const q = state.sweepSearch.toLowerCase();
    const filteredSweep = q
      ? sweepJobs.filter(j =>
          `${j.ticket_key} ${j.ticket_summary} ${j.rule_name || ''}`.toLowerCase().includes(q))
      : sweepJobs;
    const visibleSweep = filteredSweep.slice(0, state.sweepRenderLimit);
    hasMoreSweep = filteredSweep.length > visibleSweep.length;
    const countLabel = q ? `${filteredSweep.length} of ${sweepJobs.length}` : sweepJobs.length;
    html += `<div class="queue-section-header sweep-section">⟳ SWEEP <span class="section-count">${countLabel}</span><button class="btn btn-sm btn-red" style="margin-left:auto;font-size:10px;padding:2px 8px" onclick="clearSweepJobs()">🗑 Clear All</button></div>`;
    html += `<div style="padding:5px 8px;border-bottom:1px solid var(--border);background:var(--bg2)">
      <input id="sweepSearchInput" type="text" placeholder="Filter sweep tickets…" autocomplete="off"
             value="${escHtml(state.sweepSearch)}"
             style="width:100%;box-sizing:border-box;padding:4px 8px;font-size:11px;border:1px solid var(--border);border-radius:4px;background:var(--bg3);color:var(--text)">
    </div>`;
    if (visibleSweep.length) {
      html += visibleSweep.map(renderJobCard).join('');
      if (hasMoreSweep) {
        html += `<div id="sweepLoadMoreSentinel" style="padding:14px;text-align:center;color:var(--text-dim);font-size:11px;display:flex;align-items:center;justify-content:center;gap:8px">
          <span class="spinner-sm"></span> Loading more tickets…
        </div>`;
      }
    } else {
      html += `<div style="padding:14px;text-align:center;color:var(--text-dim);font-size:11px">No sweep tickets match "${escHtml(state.sweepSearch)}"</div>`;
    }
  }

  // Capture focus state before replacing DOM
  const wasSweepSearchFocused = document.activeElement?.id === 'sweepSearchInput';

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

  // Infinite scroll: when the sentinel at the bottom of the rendered sweep
  // list scrolls into view, render the next batch instead of hard-capping
  // at SWEEP_RENDER_LIMIT (the old behavior just told you to filter further).
  if (hasMoreSweep) {
    const sentinel = document.getElementById('sweepLoadMoreSentinel');
    if (sentinel) observeSweepSentinel(sentinel);
  }
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
    const count = filteredJobs().filter(j => j.status === 'queued' && j.triage !== 'closed').length;
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
    _bulkScan = null;
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
    _bulkScan = null;
    if (stopBtn) { stopBtn.style.display = 'none'; stopBtn.disabled = false; stopBtn.textContent = '⏹ Stop All'; }
    showToast('All scans stopped — queued jobs remain and can be restarted', 'warn', 5000);
    await fetchJobs();
  } catch (e) {
    if (stopBtn) { stopBtn.disabled = false; stopBtn.textContent = '⏹ Stop All'; }
    showToast('Failed to stop scans', 'error');
  }
}

async function scanAll() {
  const ids = filteredJobs().filter(j => j.status === 'queued' && j.triage !== 'closed').map(j => j.id);
  if (!ids.length) return;
  const btn = $('scanAllBtn');
  if (btn) { btn.disabled = true; btn.textContent = 'Starting…'; }
  showToast(`Starting ${ids.length} scan${ids.length !== 1 ? 's' : ''}…`, 'info', 2500);

  // Dispatch all scan requests in parallel — never sequential (blocks UI for 300 jobs)
  const results = await Promise.allSettled(
    ids.map(id => fetch(`/api/jobs/${id}/scan`, { method: 'POST' }))
  );
  let ok = 0, fail = 0;
  const startedIds = new Set();
  results.forEach((r, i) => {
    if (r.status === 'fulfilled' && r.value.ok) {
      if (state.jobs[ids[i]]) { state.jobs[ids[i]].status = 'scanning'; state.jobs[ids[i]].output_lines = []; }
      startedIds.add(ids[i]);
      ok++;
    } else { fail++; }
  });

  if (ok > 0) _bulkScan = { total: ok, ids: startedIds };

  renderJobList();
  updateStats();
  // Only open a stream for the currently selected job — never bulk-open streams
  const _sel = state.selectedJobId && state.jobs[state.selectedJobId];
  if (_sel && _sel.status === 'scanning' && !state.activeStreams[_sel.id]) openStream(_sel.id);
  if (fail === 0) showToast(`${ok} scan${ok !== 1 ? 's' : ''} started`, 'success');
  else showToast(`${ok} started · ${fail} failed to start`, 'warn');
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
  // List view only carries slim job data — fetch full detail (output_lines,
  // description, command) before rendering the detail panel.
  if (!state.jobs[jobId]?._full) {
    try {
      const res = await fetch(`/api/jobs/${jobId}`);
      if (res.ok) {
        const full = await res.json();
        full._full = true;
        state.jobs[jobId] = full;
      }
    } catch (e) { /* ignore */ }
  }
  if (state.selectedJobId === jobId) renderDetail(jobId);
}

function toggleCheck(e, jobId) {
  e.stopPropagation();
  if (e.target.checked) state.checkedIds.add(jobId);
  else state.checkedIds.delete(jobId);
  updateScanSelectedBtn();
}

function updateScanSelectedBtn() {
  const btn = $('scanSelectedBtn');
  const count = [...state.checkedIds].filter(id => {
    const j = state.jobs[id];
    return j && j.status === 'queued';
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
            <span class="meta-value">${job.ip || '—'}</span>
          </div>
          <div class="meta-item">
            <span class="meta-label">Port</span>
            <span class="meta-value">${job.port || '—'}</span>
          </div>
          <div class="meta-item">
            <span class="meta-label">CVSS</span>
            <span class="meta-value ${sevClass}">${job.ticket_cvss || '—'}</span>
          </div>
          <div class="meta-item">
            <span class="meta-label">Severity</span>
            <span class="meta-value ${sevClass}">${job.ticket_severity || '—'}</span>
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
          ${(job.status === 'completed' || job.status === 'error') && !job.jira_updated ? `
            <button class="btn btn-green" onclick="openTransition('${jobId}','Fixed')">✅ Fixed</button>
            <button class="btn btn-red"   onclick="openTransition('${jobId}','Not Fixed')">❌ Not Fixed</button>
          ` : ''}
          ${job.jira_updated ? `<span style="color:var(--green);font-size:12px">✔ Jira Updated</span>` : ''}
        </div>
      </div>

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
  const map = { queued: 'Waiting to scan', scanning: '🔍 Scanning…', completed: 'Scan complete', error: 'Scan error' };
  return map[job.status] || job.status;
}

// ── Live stream ───────────────────────────────────────────────────────────
function openStream(jobId) {
  if (state.activeStreams[jobId]) state.activeStreams[jobId].close();

  const es = new EventSource(`/api/jobs/${jobId}/stream`);
  state.activeStreams[jobId] = es;

  es.onmessage = (e) => {
    const data = JSON.parse(e.data);
    if (data.line !== undefined) {
      appendTerminalLine(jobId, data.line);
    }
    if (data.done) {
      es.close();
      delete state.activeStreams[jobId];
      // Refresh this job's state
      fetch(`/api/jobs/${jobId}`)
        .then(r => r.json())
        .then(j => {
          j._full = true;
          state.jobs[jobId] = j;
          if (state.selectedJobId === jobId) renderDetail(jobId);
          renderJobList();
          updateStats();
        });
    }
  };

  es.onerror = () => {
    es.close();
    delete state.activeStreams[jobId];
  };
}

function appendTerminalLine(jobId, line) {
  // Update in-memory job
  if (state.jobs[jobId]) {
    state.jobs[jobId].output_lines = state.jobs[jobId].output_lines || [];
    state.jobs[jobId].output_lines.push(line);
  }
  // Append to live terminal if visible
  const term = document.getElementById(`terminal-${jobId}`);
  if (term) {
    const div = document.createElement('div');
    div.className = lineClass(line);
    div.textContent = line;
    term.appendChild(div);
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
    state.jobs[jobId].status = 'scanning';
    state.jobs[jobId].output_lines = [];
    renderJobList();
    renderDetail(jobId);  // opens stream via closeOtherStreams + openStream
  } catch (e) {
    showToast(`Failed to start scan: ${e.message}`, 'error');
  }
}

async function scanSelected() {
  const ids = [...state.checkedIds].filter(id => state.jobs[id]?.status === 'queued');
  if (!ids.length) return;

  // Parallel dispatch — no sequential await loops
  const results = await Promise.allSettled(
    ids.map(id => fetch(`/api/jobs/${id}/scan`, { method: 'POST' }))
  );
  const startedIds = new Set();
  results.forEach((r, i) => {
    const id = ids[i];
    if (r.status === 'fulfilled' && r.value.ok) {
      if (state.jobs[id]) { state.jobs[id].status = 'scanning'; state.jobs[id].output_lines = []; }
      state.checkedIds.delete(id);
      startedIds.add(id);
    }
  });

  // Track as bulk scan so the Stop All button appears
  if (startedIds.size > 0) _bulkScan = { total: startedIds.size, ids: startedIds };

  renderJobList();
  updateStats();
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
  await fetch(`/api/jobs/${jobId}/reset`, { method: 'POST' });
  const res = await fetch(`/api/jobs/${jobId}`);
  const full = await res.json();
  full._full = true;
  state.jobs[jobId] = full;
  renderJobList();
  if (state.selectedJobId === jobId) renderDetail(jobId);
}

async function removeJob(jobId, e) {
  e && e.stopPropagation();
  const job = state.jobs[jobId];
  if (!job) return;
  if (!confirm(`Remove ${job.ticket_key} from queue?\nIt will re-appear on the next Jira poll if still Remediated.`)) return;
  await fetch(`/api/jobs/${jobId}`, { method: 'DELETE' });
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

function openTransition(jobId, toStatus) {
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
  return `Retest performed on ${ts} UTC\nStatus: ${toStatus}${verdict}\nNmap rule: ${job.rule_name || 'manual review'}\nTarget: ${job.ip}:${job.port}`;
}

async function confirmTransition() {
  if (!_pendingTransition) return;
  const { jobId, toStatus } = _pendingTransition;
  const comment = $('modalComment').value.trim();
  $('transitionModal').style.display = 'none';

  const ticketKey = state.jobs[jobId]?.ticket_key;

  try {
    const res = await fetch('/api/transition', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ job_id: jobId, to_status: toStatus, comment }),
    });
    if (!res.ok) {
      const err = await res.json();
      showToast(`Transition failed: ${err.detail}`, 'error');
      return;
    }

    // Server removed the job immediately — remove it locally too
    delete state.jobs[jobId];
    state.checkedIds.delete(jobId);
    if (state.selectedJobId === jobId) {
      state.selectedJobId = null;
      $('detailPanel').innerHTML = `<div class="empty-state"><div class="empty-icon">⚡</div><div>Select a ticket from the queue to view details</div></div>`;
    }

    showToast(`${ticketKey} → ${toStatus}`, 'success');
    renderJobList();
    updateStats();

  } catch (e) {
    showToast(e.message, 'error');
  }
  _pendingTransition = null;
}

// ── Bulk transition modal ─────────────────────────────────────────────────
async function openTransitionModal() {
  $('transitionPreviewBody').innerHTML = '<span style="color:var(--text-dim)">⏳ Loading…</span>';
  $('transitionTicketList').style.display = 'none';
  $('transitionTicketList').innerHTML = '';
  $('transitionConfirmBtn').disabled = true;
  $('bulkTransitionModal').style.display = 'flex';

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

    $('transitionPreviewBody').innerHTML = `
      <div style="display:flex;flex-direction:column;gap:6px">
        ${nFixed    ? `<div style="color:var(--green)">✅ <b>${nFixed}</b> ticket${nFixed!==1?'s':''} → <b>Fixed</b></div>` : ''}
        ${nNotFixed ? `<div style="color:var(--red)">❌ <b>${nNotFixed}</b> ticket${nNotFixed!==1?'s':''} → <b>Not Fixed</b></div>` : ''}
        <div style="color:var(--text-dim);font-size:11px;margin-top:4px">
          Tickets marked Open+Not Fixed, Inconclusive, or Error are excluded.
        </div>
      </div>`;

    // Build ticket list grouped by verdict
    const rows = [
      ...data.to_fixed.map(t    => ({...t, target: 'Fixed',     icon: '✅'})),
      ...data.to_not_fixed.map(t => ({...t, target: 'Not Fixed', icon: '❌'})),
    ];
    $('transitionTicketList').innerHTML = rows.map(t => `
      <div style="display:flex;align-items:center;gap:8px;padding:6px 10px;border-bottom:1px solid var(--border);font-size:11px">
        <span>${t.icon}</span>
        <span style="font-weight:600;white-space:nowrap">${escHtml(t.ticket_key)}</span>
        <span style="flex:1;color:var(--text-dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(truncate(t.ticket_summary, 55))}</span>
        <span style="color:var(--text-dim);white-space:nowrap">${escHtml(t.client_label)}</span>
      </div>`).join('');
    $('transitionTicketList').style.display = '';
    $('transitionConfirmBtn').disabled = false;
    $('transitionConfirmBtn').textContent = `Transition ${total} Ticket${total!==1?'s':''}`;
  } catch (e) {
    $('transitionPreviewBody').innerHTML = `<span style="color:var(--red)">⚠️ ${escHtml(e.message)}</span>`;
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

async function sshConnect(label) {
  // Optimistically show connecting state
  const status = await (await fetch('/api/ssh/status')).json();
  status[label] = 'connecting';
  renderSshPanel(status);

  await fetch(`/api/ssh/${label}/connect`, { method: 'POST' });
  // Poll until status changes from connecting
  let tries = 0;
  const poll = setInterval(async () => {
    tries++;
    const s = await (await fetch('/api/ssh/status')).json();
    renderSshPanel(s);
    if (s[label] !== 'connecting' || tries > 30) {
      clearInterval(poll);
      fetchLogs();
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
  state.clientFilter = e.target.value;
  state.sweepRenderLimit = 100;
  renderJobList();
  // Auto-poll Jira whenever the opco filter changes so results are always fresh
  fetch('/api/poll', { method: 'POST' }).catch(() => {});
});
$('statusFilter').addEventListener('change', e => {
  state.statusFilter = e.target.value;
  state.sweepRenderLimit = 100;
  renderJobList();
});
$('triageFilter').addEventListener('change', e => {
  state.triageFilter = e.target.value;
  state.sweepRenderLimit = 100;
  renderJobList();
});

// ── Scan selected button ──────────────────────────────────────────────────
$('scanSelectedBtn').addEventListener('click', scanSelected);

// ── Modal buttons ─────────────────────────────────────────────────────────
$('modalCancel').addEventListener('click',  () => { $('transitionModal').style.display = 'none'; _pendingTransition = null; });
$('modalConfirm').addEventListener('click', confirmTransition);
$('transitionModal').addEventListener('click', e => { if (e.target === $('transitionModal')) { $('transitionModal').style.display = 'none'; _pendingTransition = null; } });

// ── Utils ─────────────────────────────────────────────────────────────────
function escHtml(s) {
  if (!s) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function truncate(s, n) {
  if (!s) return '';
  return s.length > n ? s.slice(0, n) + '…' : s;
}

// ── Add Ticket ────────────────────────────────────────────────────────────
function openAddTicket() {
  // Populate client dropdown from clientFilter options
  const sel = $('addTicketClient');
  if (sel.options.length === 0) {
    Array.from($('clientFilter').options).slice(1).forEach(opt => {
      const o = document.createElement('option');
      o.value = opt.value;
      o.textContent = opt.textContent;
      sel.appendChild(o);
    });
  }
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
    const partialNote = data.is_partial
      ? `<div style="color:var(--yellow,#e6a817);font-size:11px">⚠️ Preview based on first ${data.sample_size} tickets — full set has ${data.total}</div>`
      : '';
    $('sweepPreviewBody').innerHTML = `
      <div style="display:flex;flex-direction:column;gap:6px">
        <div>📋 <b>${data.total}</b> total open tickets found</div>
        <div style="color:var(--green)">✅ <b>${data.to_queue}</b> have matching scan rules — will be queued</div>
        <div style="color:var(--text-dim)">⚪ <b>${data.skipped_no_rule}</b> have no matching rule — skipped</div>
        <div style="color:var(--text-dim)">⚪ <b>${data.skipped_queued}</b> already in queue — skipped</div>
        ${partialNote}
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
      $('sweepRunBtn').textContent = data.is_partial
        ? `Queue Eligible Tickets`
        : `Queue ${data.to_queue} Ticket${data.to_queue !== 1 ? 's' : ''}`;
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

async function runSweep() {
  if (!_sweepClient) return;
  const label = _sweepClient;
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
    btn.disabled    = false;
    btn.textContent = `Queue ${_sweepToQueue} Ticket${_sweepToQueue !== 1 ? 's' : ''}`;
  }
}

// ── Tab switching ─────────────────────────────────────────────────────────
function switchTab(tab) {
  const isDash     = tab === 'dashboard';
  const isReport   = tab === 'report';
  const isAssets   = tab === 'assets';
  const isShell    = tab === 'shell';
  const isSettings = tab === 'settings';

  $('tabDashboard').classList.toggle('active', isDash);
  $('tabReport').classList.toggle('active', isReport);
  $('tabAssets').classList.toggle('active', isAssets);
  $('tabShell').classList.toggle('active', isShell);
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

  if (isReport) initReportControls();
  if (isAssets) initAssetsTab();
  if (isShell) initShellTab(); else stopTunnelPolling();
  if (isSettings) initSettingsTab();
}

// ── Assets Tab ────────────────────────────────────────────────────────────
let _assetsCurrentLabel = '';

function initAssetsTab() {
  const sel = $('assetsClient');
  if (sel.options.length === 0) {
    Array.from($('clientFilter').options).slice(1).forEach(opt => {
      const o = document.createElement('option');
      o.value = opt.value;
      o.textContent = opt.textContent;
      sel.appendChild(o);
    });
  }
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
  const entries = raw.split('\n').map(s => s.trim()).filter(Boolean);
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

  try {
    const res  = await fetch(`/api/nessus/${encodeURIComponent(label)}/scans?folder_id=${folderId}`);
    const data = await res.json();
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
      return `
        <label style="display:flex;align-items:center;gap:8px;padding:4px 2px;cursor:pointer;border-bottom:1px solid var(--border)">
          <input type="checkbox" class="nessus-scan-check" value="${s.id}" onchange="_updateNessusPullBtn()" ${s.status === 'completed' ? 'checked' : ''}>
          <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(s.name)}</span>
          <span style="color:${stColor};flex-shrink:0;font-size:10px">${escHtml(s.status)}</span>
          ${dt ? `<span style="color:var(--text-dim);flex-shrink:0;font-size:10px">${dt}</span>` : ''}
        </label>`;
    }).join('');
  } catch (e) {
    group.innerHTML = _nessusFolderHeaderHtml(folderId) + `<span style="color:var(--red)">${escHtml(e.message)}</span>`;
  } finally {
    _updateNessusPullBtn();
  }
}

function _updateNessusPullBtn() {
  const any = document.querySelectorAll('.nessus-scan-check:checked').length > 0;
  $('nessusPullBtn').disabled = !any;
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

  const html = `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
      <span style="font-size:13px;font-weight:600;color:var(--text)">Cross-Reference Results</span>
      <button class="btn btn-secondary btn-sm" onclick="downloadAssetsCSV()">⬇ Download CSV</button>
    </div>

    <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:16px">
      <div class="report-card" style="padding:14px">
        <div style="font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px">Reachable (In Scope)</div>
        <div style="font-size:32px;font-weight:700;color:var(--green)">${c.in_scope_scanned || 0}</div>
        <div style="font-size:11px;color:var(--text-dim)">in asset list + found by Nessus</div>
      </div>
      <div class="report-card" style="padding:14px">
        <div style="font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px">Not Found in Scans (In Scope)</div>
        <div style="font-size:32px;font-weight:700;color:var(--orange)">${c.in_scope_missed || 0}</div>
        <div style="font-size:11px;color:var(--text-dim)">in asset list + absent from selected scans</div>
      </div>
      <div class="report-card" style="padding:14px">
        <div style="font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px">Out of Scope</div>
        <div style="font-size:32px;font-weight:700;color:var(--purple)">${c.out_of_scope || 0}</div>
        <div style="font-size:11px;color:var(--text-dim)">in Nessus scan + NOT in asset list</div>
      </div>
    </div>

    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px">
      <div class="report-card" style="padding:14px">
        <div style="font-size:11px;font-weight:600;color:var(--green);margin-bottom:10px">✅ Reachable — In Scope (${c.in_scope_scanned || 0})</div>
        <div style="line-height:2">${ipChips(data.in_scope_scanned, 'var(--green)')}</div>
      </div>
      <div class="report-card" style="padding:14px">
        <div style="font-size:11px;font-weight:600;color:var(--orange);margin-bottom:10px">⚠️ Not Found in Selected Scans — In Scope (${c.in_scope_missed || 0})</div>
        <div style="line-height:2">${ipChips(data.in_scope_missed, 'var(--orange)')}</div>
      </div>
      <div class="report-card" style="padding:14px">
        <div style="font-size:11px;font-weight:600;color:var(--purple);margin-bottom:10px">🔍 Out of Scope (${c.out_of_scope || 0})</div>
        <div style="line-height:2">${ipChips(data.out_of_scope, 'var(--purple)')}</div>
      </div>
    </div>`;

  $('assetsResults').innerHTML = html;
  $('assetsResults').scrollIntoView({ behavior: 'smooth' });
}

function downloadAssetsCSV() {
  const data = $('assetsResults')._lastResult;
  if (!data) return;

  const rows = [['IP', 'Category']];
  (data.in_scope_scanned || []).forEach(ip => rows.push([ip, 'Reachable - In Scope']));
  (data.in_scope_missed  || []).forEach(ip => rows.push([ip, 'Not Found in Selected Scans - In Scope']));
  (data.out_of_scope     || []).forEach(ip => rows.push([ip, 'Out of Scope']));

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

// ── Monthly Report ────────────────────────────────────────────────────────
function initReportControls() {
  // Populate client dropdown once
  const sel = $('reportClient');
  if (sel.options.length === 0) {
    const srcSel = $('clientFilter');
    Array.from(srcSel.options).slice(1).forEach(opt => {
      const o = document.createElement('option');
      o.value = opt.value;
      o.textContent = opt.textContent;
      sel.appendChild(o);
    });
    // Auto-generate when client or month changes
    sel.addEventListener('change', generateReport);
    $('reportMonth').addEventListener('change', generateReport);
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
        </tr>`).join('')
      : `<tr><td colspan="4" class="report-vuln-empty">No vulnerabilities to show</td></tr>`;
    return `
      <div class="report-vuln-card">
        <div class="report-card-header">New Discovered Vulnerabilities<div class="report-card-sub">${escHtml(sub)}</div></div>
        <table class="report-vuln-table">
          <thead><tr><th>Vulnerability</th><th>Issue Key</th><th>IP Address</th><th>Rating</th></tr></thead>
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
    </div>`;

  $('reportResults').innerHTML = html;
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
  if ($('transitionModal')?.style.display !== 'none')     { $('transitionModal').style.display = 'none'; _pendingTransition = null; }
});

// ── Shell Tab ─────────────────────────────────────────────────────────────
// Real interactive bash session on a client's Kali box, via xterm.js over a
// WebSocket — typed keystrokes go straight to the remote PTY, raw output
// comes straight back, just like a normal terminal.
let _shellTerm = null;
let _shellFit = null;
let _shellSocket = null;
let _shellResizeListenerAdded = false;

function initShellTab() {
  const sel = $('shellClient');
  if (sel.options.length === 0) {
    Array.from($('clientFilter').options).slice(1).forEach(opt => {
      const o = document.createElement('option');
      o.value = opt.value;
      o.textContent = opt.textContent;
      sel.appendChild(o);
    });
  }

  if (!_shellTerm) {
    _shellTerm = new Terminal({
      cursorBlink: true,
      fontSize: 13,
      fontFamily: 'Menlo, Consolas, monospace',
      theme: { background: '#0d1117', foreground: '#e6edf3' },
    });
    _shellFit = new FitAddon.FitAddon();
    _shellTerm.loadAddon(_shellFit);
    _shellTerm.open($('shellTerminalContainer'));
    _shellFit.fit();

    _shellTerm.onData((data) => {
      if (_shellSocket && _shellSocket.readyState === WebSocket.OPEN) {
        _shellSocket.send(JSON.stringify({ type: 'input', data }));
      }
    });

    if (!_shellResizeListenerAdded) {
      window.addEventListener('resize', () => {
        if (_shellTerm && $('shellView').style.display !== 'none') _shellFit.fit();
      });
      _shellResizeListenerAdded = true;
    }
  } else {
    _shellFit.fit();
  }

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
  status.textContent = `Connecting to ${label}…`;

  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(`${proto}//${location.host}/ws/shell/${encodeURIComponent(label)}`);
  _shellSocket = ws;

  ws.onopen = () => {
    _shellFit.fit();
    ws.send(JSON.stringify({ type: 'resize', cols: _shellTerm.cols, rows: _shellTerm.rows }));
    status.textContent = `Connected to ${label}`;
    _setShellConnectedUi(true);
  };

  ws.onmessage = (e) => {
    const msg = JSON.parse(e.data);
    if (msg.type === 'output') {
      _shellTerm.write(msg.data);
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

async function startTunnel() {
  const label = $('shellClient').value;
  const target = $('tunnelTarget').value.trim();
  const localPortRaw = $('tunnelLocalPort').value.trim();

  if (!label) { alert('Select a client first.'); return; }
  const m = target.match(/^([^:\s]+):(\d+)$/);
  if (!m) { alert('Target must be host:port, e.g. 127.0.0.1:8080'); return; }

  // Left blank → default to the same port locally, so pasting just
  // "host:port" into the target field is enough to start a tunnel.
  const localPort = localPortRaw ? parseInt(localPortRaw, 10) : parseInt(m[2], 10);
  if (!localPort || localPort < 1 || localPort > 65535) { alert('Enter a valid local port (1-65535).'); return; }

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
    if (!resp.ok) { alert(data.detail || 'Failed to start tunnel'); return; }
    $('tunnelTarget').value = '';
    $('tunnelLocalPort').value = '';
    refreshTunnels();
  } catch (exc) {
    alert(`Error: ${exc}`);
  }
}

async function stopTunnel(tunnelId) {
  try {
    await fetch(`/api/tunnels/${tunnelId}`, { method: 'DELETE' });
  } catch (exc) { /* ignore */ }
  refreshTunnels();
}

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
  list.innerHTML = '';

  if (tunnels.length === 0) {
    list.innerHTML = '<div style="font-size:11px;color:var(--text-dim)">No active tunnels.</div>';
    return;
  }

  tunnels.forEach((t) => {
    const row = document.createElement('div');
    row.style.cssText = 'display:flex;align-items:center;gap:10px;font-size:12px;padding:8px 12px;background:var(--bg3);border-radius:6px;flex-wrap:wrap';
    const statusColor = t.status === 'listening' ? 'var(--green)'
      : t.status === 'error' ? 'var(--red)'
      : 'var(--text-dim)';

    const openLink = t.status === 'listening'
      ? `<a href="http://localhost:${t.local_port}" target="_blank" rel="noopener" class="btn btn-secondary btn-sm">Open</a>`
      : '';
    const errorSpan = t.error ? `<span style="color:var(--red);font-size:11px">${t.error}</span>` : '';

    row.innerHTML = `
      <span style="color:${statusColor};font-weight:600;min-width:70px">${t.status}</span>
      <span style="font-weight:600">${t.label}</span>
      <span style="color:var(--text-dim)">localhost:${t.local_port} &rarr; ${t.target_host}:${t.target_port}</span>
      ${openLink}
      ${errorSpan}
      <button class="btn btn-red btn-sm" style="margin-left:auto" onclick="stopTunnel('${t.id}')">⏹ Stop</button>
    `;
    list.appendChild(row);
  });
}

// ── Settings Tab ──────────────────────────────────────────────────────────
let _settingsLoaded = false;
let _settingsRowSeq = 0;

function settingsClientRowHtml(c) {
  const rowId = `set-client-${_settingsRowSeq++}`;
  const labelLocked = !!c.label; // existing clients keep a fixed label (key into config)
  return `
    <div class="settings-client-row" id="${rowId}" data-orig-label="${escHtml(c.label || '')}">
      <button type="button" class="settings-remove-client" onclick="removeSettingsClientRow('${rowId}')" title="Remove client">✕</button>
      <div class="settings-client-row-grid">
        <div>
          <label>Label</label>
          <input type="text" class="text-input set-c-label" value="${escHtml(c.label || '')}" ${labelLocked ? 'readonly' : ''} placeholder="ClientA">
        </div>
        <div>
          <label>Display Name</label>
          <input type="text" class="text-input set-c-name" value="${escHtml(c.name || '')}" placeholder="Client A">
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
        <div></div>
        <div>
          <label>Nessus Access Key ${c.nessus_access_key_set ? '<span style="color:var(--green)">(set)</span>' : '<span style="color:var(--text-dim)">(not set)</span>'}</label>
          <input type="password" class="text-input set-c-nessusaccess" placeholder="Leave blank to keep current">
        </div>
        <div>
          <label>Nessus Secret Key ${c.nessus_secret_key_set ? '<span style="color:var(--green)">(set)</span>' : '<span style="color:var(--text-dim)">(not set)</span>'}</label>
          <input type="password" class="text-input set-c-nessussecret" placeholder="Leave blank to keep current">
        </div>
      </div>
    </div>
  `;
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

  $('setJumpHost').value     = data.jump_server.host;
  $('setJumpPort').value     = data.jump_server.port;
  $('setJumpUser').value     = data.jump_server.user;
  $('setJumpPassword').value = '';
  $('setJumpPasswordStatus').innerHTML = data.jump_server.password_set
    ? '<span style="color:var(--green)">(set — leave blank to keep)</span>'
    : '<span style="color:var(--orange)">(not set)</span>';

  $('settingsClientRows').innerHTML = data.clients.map(settingsClientRowHtml).join('')
    || '<span style="color:var(--text-dim);font-size:12px">No clients configured yet — click "+ Add Client".</span>';
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
  $('settingsClientRows').insertAdjacentHTML('beforeend', settingsClientRowHtml({}));
}

function removeSettingsClientRow(rowId) {
  const row = $(rowId);
  if (!row) return;
  const label = row.dataset.origLabel;
  if (label && !confirm(`Remove client "${label}" from config.yaml? This cannot be undone.`)) return;
  row.remove();
}

async function saveSettings() {
  const clientRows = Array.from(document.querySelectorAll('.settings-client-row'));
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

  if (!clients.length) {
    showToast('Add at least one client before saving.', 'error');
    return;
  }
  if (clients.some(c => !c.label)) {
    showToast('Every client needs a label.', 'error');
    return;
  }

  const body = {
    jira: {
      url: $('setJiraUrl').value.trim(),
      username: $('setJiraUsername').value.trim(),
      api_token: $('setJiraToken').value || null,
      project: $('setJiraProject').value.trim(),
      retest_status: $('setJiraRetestStatus').value.trim() || 'Remediated',
      poll_interval: parseInt($('setJiraPollInterval').value, 10) || 300,
    },
    jump_server: {
      host: $('setJumpHost').value.trim(),
      port: parseInt($('setJumpPort').value, 10) || 22,
      user: $('setJumpUser').value.trim(),
      password: $('setJumpPassword').value || null,
    },
    clients,
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

  await fetchConfig();
  await fetchClients();
  await fetchJobs();
  await fetchLogs();
  await fetchSshStatus();

  // Poll jobs every 5s, SSH status every 3s, logs every 15s
  setInterval(fetchJobs,      5_000);
  setInterval(fetchSshStatus, 3_000);
  setInterval(fetchLogs,     15_000);
})();
