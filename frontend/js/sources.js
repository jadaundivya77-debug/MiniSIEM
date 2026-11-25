/**
 * MiniSIEM X Log Source Health Monitoring Script
 */
document.addEventListener("DOMContentLoaded", () => {
  checkAuth();
  loadSources();
});

async function loadSources() {
  const container = document.getElementById("sources-table-body");
  if (!container) return;

  try {
    const sources = await apiFetch("/sources");
    if (!sources || sources.length === 0) {
      container.innerHTML = `<tr><td colspan="7" style="text-align:center;padding:2rem;color:#64748b;">No log sources registered.</td></tr>`;
      return;
    }

    let html = "";
    sources.forEach(s => {
      let statusClass = "status-connected";
      let badgeClass = "badge-success";
      if (s.status === "STALE") {
        statusClass = "status-stale";
        badgeClass = "badge-medium";
      } else if (s.status === "DISCONNECTED") {
        statusClass = "status-disconnected";
        badgeClass = "badge-critical";
      } else if (s.status === "DEMO") {
        statusClass = "status-demo";
        badgeClass = "badge-demo";
      }

      html += `<tr>
        <td><strong>${escapeHTML(s.name)}</strong></td>
        <td><span class="badge badge-info">${escapeHTML(s.source_type)}</span></td>
        <td class="mono">${escapeHTML(s.hostname || "-")}</td>
        <td>
          <span class="status-dot ${statusClass}"></span>
          <span class="badge ${badgeClass}">${escapeHTML(s.status)}</span>
        </td>
        <td class="mono">${formatDate(s.last_event_at)}</td>
        <td><strong>${Number(s.total_events || 0).toLocaleString()}</strong></td>
        <td>${s.error_count > 0 ? `<span class="badge badge-high">${s.error_count} Errors</span>` : `<span style="color:#10b981;">0</span>`}</td>
      </tr>`;
    });
    container.innerHTML = html;
  } catch (err) {
    showToast("Error retrieving log sources: " + err.message, "danger");
  }
}

function openAddSourceModal() {
  document.getElementById("add-source-modal")?.classList.add("active");
}

function closeAddSourceModal() {
  document.getElementById("add-source-modal")?.classList.remove("active");
}

async function submitAddSource(e) {
  e.preventDefault();
  const form = document.getElementById("add-source-form");
  const payload = {
    name: form.name.value,
    source_type: form.source_type.value,
    hostname: form.hostname.value || null,
    ip_address: form.ip_address.value || null
  };

  try {
    await apiFetch("/sources", {
      method: "POST",
      body: JSON.stringify(payload)
    });
    showToast(`Log source '${payload.name}' registered successfully!`, "success");
    closeAddSourceModal();
    form.reset();
    loadSources();
  } catch (err) {
    showToast("Registration failed: " + err.message, "danger");
  }
}

