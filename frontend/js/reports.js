/**
 * MiniSIEM X Security Health & Compliance Reports Script
 */
document.addEventListener("DOMContentLoaded", () => {
  checkAuth();
  loadReportSummary();
});

async function loadReportSummary() {
  try {
    const report = await apiFetch("/reports/summary");
    if (!report) return;

    // Render KPIs
    const kpis = report.kpis || {};
    document.getElementById("rep-total-events").innerText = Number(kpis.total_events || 0).toLocaleString();
    document.getElementById("rep-total-alerts").innerText = Number(kpis.total_alerts || 0).toLocaleString();
    document.getElementById("rep-critical-incidents").innerText = Number(kpis.critical_incidents || 0).toLocaleString();
    document.getElementById("rep-open-incidents").innerText = Number(kpis.open_incidents || 0).toLocaleString();
    document.getElementById("rep-resolved-incidents").innerText = Number(kpis.resolved_incidents || 0).toLocaleString();
    document.getElementById("rep-active-sources").innerText = Number(kpis.active_sources || 0).toLocaleString();

    // Render Top Rules Breakdown
    const rulesContainer = document.getElementById("rep-top-rules");
    if (rulesContainer) {
      let rHtml = "";
      (report.top_detection_rules || []).forEach(r => {
        rHtml += `<tr>
          <td><strong>${escapeHTML(r.rule_name)}</strong> <span class="mono" style="color:#94a3b8;">(${escapeHTML(r.rule_id)})</span></td>
          <td><span class="badge badge-critical">${r.count} Detections</span></td>
        </tr>`;
      });
      rulesContainer.innerHTML = rHtml || `<tr><td colspan="2" style="color:#64748b;">No rule triggers recorded.</td></tr>`;
    }

    // Render Recommendations
    const recContainer = document.getElementById("rep-recommendations");
    if (recContainer) {
      let recHtml = "";
      (report.recommendations || []).forEach(rec => {
        recHtml += `<li style="margin-bottom:0.5rem;color:#f8fafc;">${escapeHTML(rec)}</li>`;
      });
      recContainer.innerHTML = recHtml;
    }

  } catch (err) {
    showToast("Error compiling report summary: " + err.message, "danger");
  }
}

// Download CSV Export
async function downloadCSVReport() {
  showToast("Generating CSV report export...", "info");
  try {
    const csvContent = await apiFetch("/reports/export");
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", `minisiemx_soc_report_${new Date().toISOString().slice(0,10)}.csv`);
    document.body.appendChild(link);
    link.click();
    link.remove();
    showToast("Report exported successfully!", "success");
  } catch (err) {
    showToast("CSV export failed: " + err.message, "danger");
  }
}

// Trigger Print Dialog
function printReport() {
  window.print();
}

