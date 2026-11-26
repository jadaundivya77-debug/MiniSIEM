/**
 * MiniSIEM X Detection Rules Management Script
 */
document.addEventListener("DOMContentLoaded", () => {
  checkAuth();
  loadRules();
});

async function loadRules() {
  const container = document.getElementById("rules-grid");
  if (!container) return;

  try {
    const rules = await apiFetch("/rules");
    if (!rules || rules.length === 0) {
      container.innerHTML = `<div style="color:#64748b;padding:2rem;">No detection rules configured.</div>`;
      return;
    }

    let html = "";
    rules.forEach(r => {
      html += `
        <div class="card" style="display:flex;flex-direction:column;gap:0.75rem;">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;">
            <div>
              <span class="mono" style="font-size:0.75rem;color:#38bdf8;">${escapeHTML(r.rule_id)}</span>
              <h3 style="font-size:1rem;font-weight:700;color:#fff;margin-top:2px;">${escapeHTML(r.name)}</h3>
            </div>
            ${formatSeverityBadge(r.severity)}
          </div>

          <div style="font-size:0.82rem;color:#94a3b8;line-height:1.4;">${escapeHTML(r.description)}</div>

          <div style="background-color:var(--bg-input);padding:0.75rem;border-radius:var(--radius-sm);font-size:0.78rem;">
            <div><strong>Category:</strong> <span class="badge badge-info">${escapeHTML(r.category)}</span></div>
            <div style="display:flex;gap:0.5rem;align-items:center;margin-top:8px;">
              <label style="flex:1;">
                <span style="color:#94a3b8;">Window (s):</span>
                <input id="rule-win-${r.id}" type="number" min="5" class="form-input" style="padding:0.25rem 0.4rem;margin-top:2px;" value="${r.time_window_seconds}">
              </label>
              <label style="flex:1;">
                <span style="color:#94a3b8;">Threshold:</span>
                <input id="rule-thr-${r.id}" type="number" min="1" class="form-input" style="padding:0.25rem 0.4rem;margin-top:2px;" value="${r.threshold_count}">
              </label>
              <button class="btn btn-outline" style="padding:0.3rem 0.55rem;font-size:0.75rem;margin-top:16px;" onclick="saveRuleTuning(${r.id})">Save</button>
            </div>
            <div style="margin-top:8px;"><strong>MITRE ATT&CK:</strong> <span class="badge badge-primary">${escapeHTML(r.mitre_id || "T1078")} - ${escapeHTML(r.mitre_name || "Technique")}</span></div>
          </div>

          <div style="display:flex;align-items:center;justify-content:space-between;margin-top:auto;padding-top:0.75rem;border-top:1px solid var(--border-color);">
            <div style="display:flex;align-items:center;gap:0.5rem;">
              <span class="status-dot ${r.is_enabled ? 'status-connected' : 'status-disconnected'}"></span>
              <span style="font-size:0.8rem;color:${r.is_enabled ? '#10b981' : '#ef4444'};font-weight:600;">
                ${r.is_enabled ? "ACTIVE RULE" : "DISABLED"}
              </span>
            </div>
            <button class="btn btn-outline" style="padding:0.3rem 0.75rem;font-size:0.78rem;" onclick="toggleRuleState(${r.id}, ${!r.is_enabled})">
              <i class="fa-solid fa-power-off"></i> ${r.is_enabled ? "Disable" : "Enable"}
            </button>
          </div>
        </div>
      `;
    });
    container.innerHTML = html;
  } catch (err) {
    showToast("Error retrieving detection rules: " + err.message, "danger");
  }
}

async function toggleRuleState(id, newState) {
  try {
    await apiFetch(`/rules/${id}`, {
      method: "PATCH",
      body: JSON.stringify({ is_enabled: newState })
    });
    showToast(`Rule state updated!`, "success");
    loadRules();
  } catch (err) {
    showToast("Failed to update rule state: " + err.message, "danger");
  }
}

async function saveRuleTuning(id) {
  const winVal = parseInt(document.getElementById(`rule-win-${id}`)?.value || "120", 10);
  const thrVal = parseInt(document.getElementById(`rule-thr-${id}`)?.value || "5", 10);
  if (isNaN(winVal) || winVal < 5 || isNaN(thrVal) || thrVal < 1) {
    showToast("Window must be >= 5s and Threshold >= 1.", "danger");
    return;
  }
  try {
    await apiFetch(`/rules/${id}`, {
      method: "PATCH",
      body: JSON.stringify({ time_window_seconds: winVal, threshold_count: thrVal })
    });
    showToast(`Saved rule thresholds (window=${winVal}s, threshold=${thrVal})!`, "success");
    loadRules();
  } catch (err) {
    showToast("Failed to save rule thresholds: " + err.message, "danger");
  }
}

