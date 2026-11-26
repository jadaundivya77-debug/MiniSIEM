/**
 * MiniSIEM X Threat Alerts Script
 * Handles alert triage, explainability inspection drawer, MITRE mapping, and status updates.
 */

let activeAlertFilter = {
  status: "",
  severity: "",
  search: ""
};
let currentInspectedAlert = null;

document.addEventListener("DOMContentLoaded", () => {
  checkAuth();
  loadAlerts();
  initAlertFilters();
  setInterval(() => loadAlerts(true), CONFIG.REFRESH_INTERVAL_MS);
});

async function loadAlerts(silent = false) {
  const tbody = document.getElementById("alerts-table-body");
  if (!tbody) return;

  let query = `/alerts?limit=100`;
  if (activeAlertFilter.status) query += `&status=${encodeURIComponent(activeAlertFilter.status)}`;
  if (activeAlertFilter.severity) query += `&severity=${encodeURIComponent(activeAlertFilter.severity)}`;
  if (activeAlertFilter.search) query += `&search=${encodeURIComponent(activeAlertFilter.search)}`;

  try {
    const alerts = await apiFetch(query);
    if (!alerts || alerts.length === 0) {
      tbody.innerHTML = `<tr><td colspan="9" style="text-align:center;padding:2.5rem;color:#64748b;">No security alerts found.</td></tr>`;
      return;
    }

    let html = "";
    alerts.forEach(a => {
      html += `<tr>
        <td class="mono">#ALT-${a.id}</td>
        <td><strong>${escapeHTML(a.title)}</strong><br><span style="font-size:0.75rem;color:#94a3b8;">${escapeHTML(a.rule_name)} (${a.event_count} events)</span></td>
        <td>${formatOriginBadge(a.is_demo)}</td>
        <td>${formatSeverityBadge(a.severity)}</td>
        <td>${formatStatusBadge(a.status)}</td>
        <td class="mono" style="color:#38bdf8;">${escapeHTML(a.source_ip || "Local / -")}</td>
        <td>${a.target_username ? `<code>${escapeHTML(a.target_username)}</code>` : "-"}</td>
        <td><span class="badge badge-info">${escapeHTML(a.mitre_technique_id || "N/A")}</span></td>
        <td>
          <button class="btn btn-primary" style="padding:0.25rem 0.65rem;font-size:0.75rem;" onclick="openAlertDetail(${a.id})">
            <i class="fa-solid fa-magnifying-glass"></i> Inspect
          </button>
        </td>
      </tr>`;
    });
    tbody.innerHTML = html;
  } catch (err) {
    if (!silent) {
      showToast("Error retrieving alerts: " + err.message, "danger");
    }
  }
}

function initAlertFilters() {
  document.getElementById("alert-status-filter")?.addEventListener("change", (e) => {
    activeAlertFilter.status = e.target.value;
    loadAlerts();
  });
  document.getElementById("alert-severity-filter")?.addEventListener("change", (e) => {
    activeAlertFilter.severity = e.target.value;
    loadAlerts();
  });
  document.getElementById("alert-search")?.addEventListener("input", (e) => {
    activeAlertFilter.search = e.target.value.trim();
    loadAlerts();
  });
}

// Open Explainable Alert Detail Drawer
async function openAlertDetail(id) {
  try {
    const alert = await apiFetch(`/alerts/${id}`);
    if (!alert) return;
    currentInspectedAlert = alert;

    document.getElementById("drawer-alert-id").innerText = `#ALT-${alert.id}`;
    document.getElementById("drawer-alert-title").innerText = alert.title;
    const originEl = document.getElementById("drawer-alert-origin");
    if (originEl) originEl.innerHTML = formatOriginBadge(alert.is_demo);
    document.getElementById("drawer-alert-severity").innerHTML = formatSeverityBadge(alert.severity);
    document.getElementById("drawer-alert-status").innerHTML = formatStatusBadge(alert.status);
    document.getElementById("drawer-alert-time").innerText = formatDate(alert.created_at);

    // Telemetry specifics
    document.getElementById("drawer-alert-ip").innerText = alert.source_ip || "Local / Unspecified";
    document.getElementById("drawer-alert-user").innerText = alert.target_username || "N/A";
    document.getElementById("drawer-alert-asset").innerText = alert.affected_asset || "N/A";
    document.getElementById("drawer-alert-rule").innerText = `${alert.rule_name} (${alert.rule_id})`;

    // MITRE Mapping
    document.getElementById("drawer-mitre-tech").innerText = `${alert.mitre_technique_id || "N/A"} - ${alert.mitre_technique_name || "N/A"}`;
    document.getElementById("drawer-mitre-tactic").innerText = alert.mitre_tactic || "N/A";

    // EXPLAINABILITY: What Happened & Why Suspicious
    let formattedExplanation = escapeHTML(alert.explanation || "No explanation recorded.")
      .replace(/WHAT HAPPENED:/g, '<strong style="color:#38bdf8;">WHAT HAPPENED:</strong>')
      .replace(/WHY IS IT SUSPICIOUS:/g, '<strong style="color:#f87171;">WHY IS IT SUSPICIOUS:</strong>')
      .replace(/TRIGGERED RULE:/g, '<strong style="color:#a78bfa;">TRIGGERED RULE:</strong>')
      .replace(/EVIDENCE SUMMARY:/g, '<strong style="color:#34d399;">EVIDENCE SUMMARY:</strong>')
      .replace(/\n/g, '<br>');
    document.getElementById("drawer-explanation").innerHTML = formattedExplanation;

    // SOP Checklist
    let formattedSOP = escapeHTML(alert.recommended_actions || "Follow general SOC triage playbook.")
      .replace(/\n/g, '<br>');
    document.getElementById("drawer-sop").innerHTML = formattedSOP;

    // Raw Evidence Box
    let evidenceObj = {};
    try {
      evidenceObj = JSON.parse(alert.raw_evidence_json || "{}");
    } catch (e) {
      evidenceObj = { raw: alert.raw_evidence_json };
    }
    document.getElementById("drawer-evidence").innerText = JSON.stringify(evidenceObj, null, 2);

    // Set active alert ID in status update form
    document.getElementById("drawer-update-alert-id").value = alert.id;
    document.getElementById("drawer-status-select").value = alert.status;

    // Open drawer
    document.getElementById("alert-detail-drawer")?.classList.add("open");
  } catch (err) {
    showToast("Error loading alert detail: " + err.message, "danger");
  }
}

function closeAlertDrawer() {
  document.getElementById("alert-detail-drawer")?.classList.remove("open");
}

// Update Alert Status
async function submitAlertStatusUpdate() {
  const alertId = document.getElementById("drawer-update-alert-id").value;
  const newStatus = document.getElementById("drawer-status-select").value;
  const notes = document.getElementById("drawer-notes-input").value;

  try {
    await apiFetch(`/alerts/${alertId}`, {
      method: "PATCH",
      body: JSON.stringify({ status: newStatus, notes: notes })
    });
    showToast(`Alert #${alertId} updated to ${newStatus}`, "success");
    closeAlertDrawer();
    loadAlerts();
  } catch (err) {
    showToast("Failed to update alert: " + err.message, "danger");
  }
}

async function escalateAlertToIncident() {
  if (!currentInspectedAlert) return;
  const a = currentInspectedAlert;
  try {
    let relatedLogs = [];
    if (a.target_username || a.source_ip) {
      const params = new URLSearchParams({ limit: "10" });
      if (a.target_username) params.set("username", a.target_username);
      if (a.source_ip) params.set("source_ip", a.source_ip);
      const logs = await apiFetch(`/logs?${params.toString()}`);
      if (Array.isArray(logs)) relatedLogs = logs.map(l => l.id);
    }
    const inc = await apiFetch("/incidents", {
      method: "POST",
      body: JSON.stringify({
        title: `Incident: ${a.title}`,
        description: a.description || `Escalated from alert #ALT-${a.id} (${a.rule_name})`,
        severity: a.severity,
        assigned_analyst: "analyst",
        investigation_notes: `Escalated from alert #ALT-${a.id} on asset ${a.affected_asset || "host"}.`,
        related_alert_ids: [a.id],
        related_log_ids: relatedLogs
      })
    });
    showToast(`Created incident ${inc.incident_number} with ${inc.events_count || 0} linked event(s)!`, "success");
    closeAlertDrawer();
  } catch (err) {
    showToast("Failed to create incident: " + err.message, "danger");
  }
}

