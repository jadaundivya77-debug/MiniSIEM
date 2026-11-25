/**
 * MiniSIEM X Asset Inventory & Risk Posture Script
 */
document.addEventListener("DOMContentLoaded", () => {
  checkAuth();
  loadAssets();
});

async function loadAssets() {
  const container = document.getElementById("assets-table-body");
  if (!container) return;

  try {
    const assets = await apiFetch("/assets");
    if (!assets || assets.length === 0) {
      container.innerHTML = `<tr><td colspan="8" style="text-align:center;padding:2rem;color:#64748b;">No assets in inventory.</td></tr>`;
      return;
    }

    let html = "";
    assets.forEach(a => {
      let scoreColor = "#10b981";
      if (a.risk_score >= 80) scoreColor = "#ef4444";
      else if (a.risk_score >= 55) scoreColor = "#f97316";
      else if (a.risk_score >= 30) scoreColor = "#eab308";

      html += `<tr>
        <td><strong>${escapeHTML(a.name)}</strong></td>
        <td class="mono" style="color:#38bdf8;">${escapeHTML(a.hostname)}</td>
        <td class="mono">${escapeHTML(a.ip_address)}</td>
        <td><span class="badge badge-info">${escapeHTML(a.asset_type)}</span></td>
        <td><span class="badge badge-medium">${escapeHTML(a.criticality)}</span></td>
        <td>
          <div style="display:flex;align-items:center;gap:0.5rem;">
            <strong style="color:${scoreColor};font-size:1.1rem;">${a.risk_score}</strong>
            <span class="badge ${a.risk_level === 'CRITICAL' ? 'badge-critical' : (a.risk_level === 'HIGH' ? 'badge-high' : 'badge-low')}">${a.risk_level}</span>
          </div>
        </td>
        <td><span class="badge badge-critical">${a.associated_alerts_count} Alerts</span></td>
        <td>
          <button class="btn btn-outline" style="padding:0.25rem 0.6rem;font-size:0.75rem;" onclick="viewAssetRiskBreakdown(${a.id})">
            <i class="fa-solid fa-calculator"></i> Explain Risk
          </button>
        </td>
      </tr>`;
    });
    container.innerHTML = html;
  } catch (err) {
    showToast("Error retrieving assets: " + err.message, "danger");
  }
}

// Explainable Risk Breakdown Modal
async function viewAssetRiskBreakdown(id) {
  try {
    const asset = await apiFetch(`/assets/${id}`);
    if (!asset) return;

    document.getElementById("risk-modal-asset-name").innerText = `${asset.name} (${asset.hostname})`;
    document.getElementById("risk-modal-score").innerText = `${asset.risk_score} / 100 (${asset.risk_level} RISK)`;
    document.getElementById("risk-modal-asset-id").value = asset.id;

    let factors = {};
    try {
      factors = JSON.parse(asset.risk_factors_json || "{}");
    } catch (e) {
      factors = {};
    }

    let html = `
      <div style="display:flex;flex-direction:column;gap:1rem;">
        <div style="background-color:var(--bg-input);padding:0.85rem;border-radius:var(--radius-sm);border-left:3px solid var(--accent-indigo);">
          <strong style="color:#38bdf8;">1. Baseline Criticality Weight</strong>
          <div style="font-size:0.85rem;margin-top:0.25rem;">
            Asset Category: <strong>${asset.criticality}</strong> | Contributed: <strong>${factors.asset_criticality?.points_contributed || 10} pts</strong>
          </div>
          <div style="font-size:0.75rem;color:#94a3b8;">${factors.asset_criticality?.explanation || "Baseline tier contribution."}</div>
        </div>

        <div style="background-color:var(--bg-input);padding:0.85rem;border-radius:var(--radius-sm);border-left:3px solid var(--severity-high);">
          <strong style="color:#f97316;">2. Associated Threat Alerts</strong>
          <div style="font-size:0.85rem;margin-top:0.25rem;">
            Total Triggered Alerts: <strong>${factors.alert_threats?.total_associated_alerts || asset.associated_alerts_count}</strong> | Contributed: <strong>${factors.alert_threats?.points_contributed || 0} pts</strong>
          </div>
          <div style="font-size:0.75rem;color:#94a3b8;">Calculated using severity weights (Critical=30pts, High=20pts, Medium=10pts).</div>
        </div>

        <div style="background-color:var(--bg-input);padding:0.85rem;border-radius:var(--radius-sm);border-left:3px solid var(--severity-critical);">
          <strong style="color:#ef4444;">3. Active Open Incidents Multiplier</strong>
          <div style="font-size:0.85rem;margin-top:0.25rem;">
            Unresolved Incidents: <strong>${factors.open_incidents?.open_incident_count || 0}</strong> | Contributed: <strong>${factors.open_incidents?.points_contributed || 0} pts</strong>
          </div>
          <div style="font-size:0.75rem;color:#94a3b8;">Active unresolved compromise chains dramatically increase target vulnerability score.</div>
        </div>
      </div>
    `;

    document.getElementById("risk-modal-factors").innerHTML = html;
    document.getElementById("asset-risk-modal")?.classList.add("active");
  } catch (err) {
    showToast("Error inspecting asset risk: " + err.message, "danger");
  }
}

function closeAssetRiskModal() {
  document.getElementById("asset-risk-modal")?.classList.remove("active");
}

async function triggerRecalculateRisk() {
  const assetId = document.getElementById("risk-modal-asset-id").value;
  try {
    await apiFetch(`/assets/${assetId}/recalculate`, { method: "POST" });
    showToast("Asset risk recomputed successfully!", "success");
    closeAssetRiskModal();
    loadAssets();
  } catch (err) {
    showToast("Recalculation error: " + err.message, "danger");
  }
}

