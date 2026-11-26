/**
 * MiniSIEM X Live Logs Monitoring Script
 * Handles real-time event streaming, filtering, manual log injection, and file ingestion.
 */

let activeLogFilter = {
  search: "",
  source: "",
  severity: "",
  is_demo: "",
  limit: 50
};
let logsAutoRefreshEnabled = true;
let logsRefreshTimer = null;

document.addEventListener("DOMContentLoaded", () => {
  checkAuth();
  loadLogs();
  initLogEventListeners();
  startLogsPolling();
});

function startLogsPolling() {
  if (logsRefreshTimer) clearInterval(logsRefreshTimer);
  logsRefreshTimer = setInterval(() => {
    if (logsAutoRefreshEnabled) {
      loadLogs(true);
    }
  }, 4000);
}

function toggleLogsAutoRefresh() {
  logsAutoRefreshEnabled = !logsAutoRefreshEnabled;
  const btn = document.getElementById("logs-autorefresh-btn");
  if (btn) {
    btn.innerHTML = logsAutoRefreshEnabled
      ? `<span class="status-dot status-connected"></span> Auto-Refresh: ON`
      : `<span class="status-dot status-disconnected"></span> Auto-Refresh: OFF`;
  }
}

async function loadLogs(silent = false) {
  const tbody = document.getElementById("logs-table-body");
  if (!tbody) return;

  let query = `/logs?limit=${activeLogFilter.limit}`;
  if (activeLogFilter.search) query += `&search=${encodeURIComponent(activeLogFilter.search)}`;
  if (activeLogFilter.source) query += `&source=${encodeURIComponent(activeLogFilter.source)}`;
  if (activeLogFilter.severity) query += `&severity=${encodeURIComponent(activeLogFilter.severity)}`;
  if (activeLogFilter.is_demo !== "") query += `&is_demo=${encodeURIComponent(activeLogFilter.is_demo)}`;

  try {
    const logs = await apiFetch(query);
    if (!logs || logs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;padding:2rem;color:#64748b;">No log events matched your criteria.</td></tr>`;
      return;
    }

    let html = "";
    logs.forEach(l => {
      html += `<tr>
        <td class="mono">${formatDate(l.timestamp)}</td>
        <td>
          <span class="badge badge-info">${escapeHTML(l.source)}</span>
          ${l.hostname ? `<div class="mono" style="font-size:0.7rem;color:#94a3b8;margin-top:2px;">${escapeHTML(l.hostname)}</div>` : ""}
        </td>
        <td>${formatOriginBadge(l.is_demo)}</td>
        <td><strong>${escapeHTML(l.event_type)}</strong></td>
        <td>${l.username ? `<code>${escapeHTML(l.username)}</code>` : '<span style="color:#64748b;">-</span>'}</td>
        <td class="mono" style="color:#38bdf8;">${escapeHTML(l.source_ip || "Local / -")}</td>
        <td>${formatSeverityBadge(l.severity)}</td>
        <td>
          <button class="btn btn-outline" style="padding:0.25rem 0.6rem;font-size:0.75rem;" onclick="viewRawLog(${l.id})">
            <i class="fa-solid fa-code"></i> Raw
          </button>
        </td>
      </tr>`;
    });
    tbody.innerHTML = html;
  } catch (err) {
    if (!silent) {
      showToast("Error retrieving logs: " + err.message, "danger");
    }
  }
}

function initLogEventListeners() {
  // Search filter
  const searchInput = document.getElementById("log-search");
  if (searchInput) {
    searchInput.addEventListener("input", (e) => {
      activeLogFilter.search = e.target.value.trim();
      loadLogs();
    });
  }

  // Source filter
  const sourceSelect = document.getElementById("log-source-filter");
  if (sourceSelect) {
    sourceSelect.addEventListener("change", (e) => {
      activeLogFilter.source = e.target.value;
      loadLogs();
    });
  }

  // Severity filter
  const sevSelect = document.getElementById("log-severity-filter");
  if (sevSelect) {
    sevSelect.addEventListener("change", (e) => {
      activeLogFilter.severity = e.target.value;
      loadLogs();
    });
  }

  // Origin filter (Real vs Simulated)
  const originSelect = document.getElementById("log-origin-filter");
  if (originSelect) {
    originSelect.addEventListener("change", (e) => {
      activeLogFilter.is_demo = e.target.value;
      loadLogs();
    });
  }
}

// Inspect Raw Log Modal
async function viewRawLog(id) {
  try {
    const log = await apiFetch(`/logs/${id}`);
    if (!log) return;

    document.getElementById("raw-modal-title").innerText = `Event #${log.id}: ${log.event_type} (${log.is_demo ? "SIMULATED" : "REAL"})`;
    document.getElementById("raw-modal-content").innerText =
      `Source: ${log.source} | Host: ${log.hostname || "-"} | User: ${log.username || "-"} | IP: ${log.source_ip || "Local / -"} | Time: ${formatDate(log.timestamp)}\n\n` +
      (log.raw_event || JSON.stringify(log, null, 2));
    document.getElementById("raw-modal-meta").innerText = log.metadata_json ? JSON.stringify(JSON.parse(log.metadata_json), null, 2) : "None";
    document.getElementById("raw-log-modal").classList.add("active");
  } catch (err) {
    showToast("Error loading raw log: " + err.message, "danger");
  }
}

function closeRawLogModal() {
  document.getElementById("raw-log-modal")?.classList.remove("active");
}

// Ingest Manual Event Modal
function openManualIngestModal() {
  document.getElementById("manual-ingest-modal")?.classList.add("active");
}

function closeManualIngestModal() {
  document.getElementById("manual-ingest-modal")?.classList.remove("active");
}

async function submitManualLog(e) {
  e.preventDefault();
  const form = document.getElementById("manual-log-form");
  const payload = {
    source: form.source.value,
    event_type: form.event_type.value,
    username: form.username.value || null,
    source_ip: form.source_ip.value || null,
    destination_ip: form.destination_ip.value || null,
    destination_port: form.destination_port.value ? parseInt(form.destination_port.value) : null,
    severity: form.severity.value,
    raw_event: form.raw_event.value || `Manual ingestion: ${form.event_type.value}`,
    is_demo: false
  };

  try {
    await apiFetch("/logs/ingest", {
      method: "POST",
      body: JSON.stringify(payload)
    });
    showToast("Log event successfully ingested & processed through detection engine!", "success");
    closeManualIngestModal();
    form.reset();
    loadLogs();
  } catch (err) {
    showToast("Ingestion failed: " + err.message, "danger");
  }
}

// File Upload Handler
function openUploadModal() {
  document.getElementById("upload-log-modal")?.classList.add("active");
}

function closeUploadModal() {
  document.getElementById("upload-log-modal")?.classList.remove("active");
}

async function handleFileUpload(e) {
  e.preventDefault();
  const fileInput = document.getElementById("log-file-input");
  const sourceName = document.getElementById("upload-source-name")?.value || "file_import";

  if (!fileInput.files || fileInput.files.length === 0) {
    showToast("Please select a log file (JSON, JSONL, CSV, Text)", "danger");
    return;
  }

  const formData = new FormData();
  formData.append("file", fileInput.files[0]);
  formData.append("source_name", sourceName);

  showToast("Uploading and parsing log file...", "info");

  try {
    const res = await apiFetch("/logs/upload", {
      method: "POST",
      body: formData
    });

    showToast(
      `File ingested! Ingested ${res.total_ingested} records (${res.total_errors} errors).`,
      "success"
    );
    closeUploadModal();
    loadLogs();
  } catch (err) {
    showToast("File upload failed: " + err.message, "danger");
  }
}

