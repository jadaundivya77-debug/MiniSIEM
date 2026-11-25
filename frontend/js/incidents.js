/**
 * MiniSIEM X Incident Management Script
 * Handles incident tracking, attack story timeline display, analyst notes, and status lifecycle.
 */

let activeIncidentFilter = {
  status: "",
  severity: "",
  search: ""
};

document.addEventListener("DOMContentLoaded", () => {
  checkAuth();
  loadIncidents();
  initIncidentFilters();
});

async function loadIncidents() {
  const grid = document.getElementById("incidents-grid");
  if (!grid) return;

  let query = `/incidents?limit=50`;
  if (activeIncidentFilter.status) query += `&status=${encodeURIComponent(activeIncidentFilter.status)}`;
  if (activeIncidentFilter.severity) query += `&severity=${encodeURIComponent(activeIncidentFilter.severity)}`;
  if (activeIncidentFilter.search) query += `&search=${encodeURIComponent(activeIncidentFilter.search)}`;

  try {
    const incidents = await apiFetch(query);
    if (!incidents || incidents.length === 0) {
      grid.innerHTML = `<div style="grid-column: 1/-1;text-align:center;padding:3rem;color:#64748b;">No security incidents found.</div>`;
      return;
    }

    let html = "";
    incidents.forEach(inc => {
      const isCritical = inc.severity === "CRITICAL";
      const cardClass = isCritical ? "card-critical" : (inc.severity === "HIGH" ? "card-high" : "card-medium");

      html += `
        <div class="incident-card ${cardClass}">
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <span class="incident-num">${escapeHTML(inc.incident_number)}</span>
            ${formatSeverityBadge(inc.severity)}
          </div>
          <div class="incident-title">${escapeHTML(inc.title)}</div>
          <div style="font-size:0.8rem;color:#94a3b8;line-height:1.4;">${escapeHTML(inc.description)}</div>
          
          <div class="incident-meta">
            <div><i class="fa-solid fa-clock"></i> ${formatDate(inc.created_at)}</div>
            <div><i class="fa-solid fa-user-tag"></i> ${escapeHTML(inc.assigned_analyst || "Unassigned")}</div>
            <div><i class="fa-solid fa-link"></i> ${inc.events_count || 0} Events</div>
          </div>

          <div class="incident-footer">
            <div>${formatStatusBadge(inc.status)}</div>
            <button class="btn btn-outline" style="padding:0.3rem 0.75rem;font-size:0.78rem;" onclick="viewIncidentStory(${inc.id})">
              <i class="fa-solid fa-route"></i> Attack Story
            </button>
          </div>
        </div>
      `;
    });
    grid.innerHTML = html;
  } catch (err) {
    showToast("Error retrieving incidents: " + err.message, "danger");
  }
}

function initIncidentFilters() {
  document.getElementById("incident-status-filter")?.addEventListener("change", (e) => {
    activeIncidentFilter.status = e.target.value;
    loadIncidents();
  });
  document.getElementById("incident-severity-filter")?.addEventListener("change", (e) => {
    activeIncidentFilter.severity = e.target.value;
    loadIncidents();
  });
  document.getElementById("incident-search")?.addEventListener("input", (e) => {
    activeIncidentFilter.search = e.target.value.trim();
    loadIncidents();
  });
}

// View Incident Attack Story Timeline
async function viewIncidentStory(id) {
  try {
    const [inc, timelineData] = await Promise.all([
      apiFetch(`/incidents/${id}`),
      apiFetch(`/incidents/${id}/timeline`)
    ]);

    if (!inc) return;

    document.getElementById("story-modal-num").innerText = inc.incident_number;
    document.getElementById("story-modal-title").innerText = inc.title;
    document.getElementById("story-modal-status").innerHTML = formatStatusBadge(inc.status);
    document.getElementById("story-modal-severity").innerHTML = formatSeverityBadge(inc.severity);
    document.getElementById("story-modal-analyst").innerText = inc.assigned_analyst || "Unassigned";

    // Narrative Box
    document.getElementById("story-modal-narrative").innerText = inc.attack_story || "No chronological narrative compiled yet.";

    // Render Timeline Steps
    const timelineContainer = document.getElementById("story-timeline-container");
    const steps = timelineData.timeline || [];

    if (steps.length === 0) {
      timelineContainer.innerHTML = `<div style="color:#64748b;padding:1rem;">No individual event steps correlated.</div>`;
    } else {
      let tHtml = "";
      steps.forEach(st => {
        tHtml += `
          <div class="story-step">
            <div class="story-step-header">
              <div class="story-step-stage">${escapeHTML(st.stage)}</div>
              <div class="mono" style="font-size:0.75rem;color:#94a3b8;">${formatDate(st.created_at)}</div>
            </div>
            <div class="story-step-desc">
              ${escapeHTML(st.note || "")}
              ${st.log ? `<br><span class="mono" style="font-size:0.72rem;color:#38bdf8;">[Telemetry #${st.log.id}: ${escapeHTML(st.log.event_type)} from ${escapeHTML(st.log.source_ip || "-")}]</span>` : ""}
            </div>
          </div>
        `;
      });
      timelineContainer.innerHTML = tHtml;
    }

    // Set update form values
    document.getElementById("incident-update-id").value = inc.id;
    document.getElementById("incident-status-update").value = inc.status;
    document.getElementById("incident-analyst-update").value = inc.assigned_analyst || "";
    document.getElementById("incident-notes-update").value = inc.investigation_notes || "";

    // Open modal
    document.getElementById("incident-story-modal")?.classList.add("active");
  } catch (err) {
    showToast("Error loading incident story: " + err.message, "danger");
  }
}

function closeIncidentStoryModal() {
  document.getElementById("incident-story-modal")?.classList.remove("active");
}

// Update Incident Status & Analyst Notes
async function submitIncidentUpdate() {
  const id = document.getElementById("incident-update-id").value;
  const status = document.getElementById("incident-status-update").value;
  const analyst = document.getElementById("incident-analyst-update").value;
  const notes = document.getElementById("incident-notes-update").value;

  try {
    await apiFetch(`/incidents/${id}`, {
      method: "PATCH",
      body: JSON.stringify({
        status: status,
        assigned_analyst: analyst,
        investigation_notes: notes
      })
    });
    showToast(`Incident #${id} successfully updated!`, "success");
    closeIncidentStoryModal();
    loadIncidents();
  } catch (err) {
    showToast("Failed to update incident: " + err.message, "danger");
  }
}

