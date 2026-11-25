/**
 * MiniSIEM X Dashboard Script
 * Manages live telemetry retrieval, Chart.js visualizations, and KPI rendering.
 */
let charts = {};

document.addEventListener("DOMContentLoaded", () => {
  checkAuth();
  loadDashboardStats();
  // Auto-refresh interval
  setInterval(loadDashboardStats, CONFIG.REFRESH_INTERVAL_MS);
});

async function loadDashboardStats() {
  try {
    const [stats, timeline] = await Promise.all([
      apiFetch("/dashboard/stats"),
      apiFetch("/dashboard/timeline")
    ]);

    if (!stats) return;

    renderKPIs(stats);
    renderCharts(stats);
    renderRiskyAssets(stats.top_risky_assets || []);
    renderSuspiciousIPs(stats.top_suspicious_ips || []);
    renderTimeline(timeline || []);
  } catch (err) {
    console.error("Dashboard data load error:", err);
  }
}

function renderKPIs(stats) {
  document.getElementById("kpi-events").innerText = Number(stats.total_events || 0).toLocaleString();
  document.getElementById("kpi-alerts").innerText = Number(stats.total_alerts || 0).toLocaleString();
  document.getElementById("kpi-critical").innerText = Number(stats.critical_incidents || 0).toLocaleString();
  document.getElementById("kpi-sources").innerText = Number(stats.active_sources || 0).toLocaleString();
  document.getElementById("kpi-open-incidents").innerText = Number(stats.open_incidents || 0).toLocaleString();
  document.getElementById("kpi-today-events").innerText = Number(stats.events_processed_today || 0).toLocaleString();

  // Demo Mode Indicator
  const demoBanner = document.getElementById("demo-mode-indicator");
  if (demoBanner) {
    if (stats.is_demo) {
      demoBanner.style.display = "inline-flex";
    } else {
      demoBanner.style.display = "none";
    }
  }

  // Engine Status
  const engineEl = document.getElementById("engine-status-text");
  if (engineEl && stats.detection_engine_status) {
    engineEl.innerHTML = `
      <span class="status-dot status-connected"></span>
      Engine Active (${stats.detection_engine_status.active_rules}/${stats.detection_engine_status.total_rules} Rules Enabled)
    `;
  }
}

function renderCharts(stats) {
  // Chart 1: Severity Doughnut
  const sevData = stats.alerts_by_severity || {};
  const ctxSev = document.getElementById("chart-severity")?.getContext("2d");
  if (ctxSev) {
    if (charts.severity) charts.severity.destroy();
    charts.severity = new Chart(ctxSev, {
      type: "doughnut",
      data: {
        labels: ["Critical", "High", "Medium", "Low"],
        datasets: [{
          data: [
            sevData.CRITICAL || 0,
            sevData.HIGH || 0,
            sevData.MEDIUM || 0,
            sevData.LOW || 0
          ],
          backgroundColor: ["#EF4444", "#F97316", "#EAB308", "#3B82F6"],
          borderWidth: 0
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: "bottom", labels: { color: "#94a3b8", boxWidth: 12 } }
        },
        cutout: "70%"
      }
    });
  }

  // Chart 2: Attack Types Bar Chart
  const attackTypes = stats.top_attack_types || [];
  const ctxAttack = document.getElementById("chart-attacks")?.getContext("2d");
  if (ctxAttack) {
    if (charts.attacks) charts.attacks.destroy();
    charts.attacks = new Chart(ctxAttack, {
      type: "bar",
      data: {
        labels: attackTypes.map(a => a.name.length > 20 ? a.name.substring(0, 18) + '...' : a.name),
        datasets: [{
          label: "Alerts Triggered",
          data: attackTypes.map(a => a.count),
          backgroundColor: "#8B5CF6",
          borderRadius: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false }
        },
        scales: {
          x: { ticks: { color: "#94a3b8", font: { size: 10 } }, grid: { display: false } },
          y: { ticks: { color: "#94a3b8", stepSize: 1 }, grid: { color: "#1e293b" } }
        }
      }
    });
  }

  // Chart 3: Events by Source Pie Chart
  const sourceEvents = stats.events_by_source || [];
  const ctxSource = document.getElementById("chart-sources")?.getContext("2d");
  if (ctxSource) {
    if (charts.sources) charts.sources.destroy();
    charts.sources = new Chart(ctxSource, {
      type: "pie",
      data: {
        labels: sourceEvents.map(s => s.source.toUpperCase()),
        datasets: [{
          data: sourceEvents.map(s => s.count),
          backgroundColor: ["#6366F1", "#06B6D4", "#10B981", "#EC4899", "#8B5CF6"],
          borderWidth: 0
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: "bottom", labels: { color: "#94a3b8", boxWidth: 12 } }
        }
      }
    });
  }

  // Chart 4: Events Volume Simulation Timeline
  const ctxEvents = document.getElementById("chart-events")?.getContext("2d");
  if (ctxEvents) {
    if (charts.events) charts.events.destroy();
    charts.events = new Chart(ctxEvents, {
      type: "line",
      data: {
        labels: ["T-50m", "T-40m", "T-30m", "T-20m", "T-10m", "Current"],
        datasets: [{
          label: "Log Intake Rate",
          data: [
            Math.max(2, Math.floor(stats.total_events * 0.1)),
            Math.max(5, Math.floor(stats.total_events * 0.25)),
            Math.max(8, Math.floor(stats.total_events * 0.4)),
            Math.max(12, Math.floor(stats.total_events * 0.65)),
            Math.max(15, Math.floor(stats.total_events * 0.85)),
            stats.total_events || 20
          ],
          borderColor: "#06B6D4",
          backgroundColor: "rgba(6, 182, 212, 0.15)",
          fill: true,
          tension: 0.35,
          pointRadius: 4,
          pointBackgroundColor: "#06B6D4"
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: "#94a3b8" }, grid: { display: false } },
          y: { ticks: { color: "#94a3b8" }, grid: { color: "#1e293b" } }
        }
      }
    });
  }
}

function renderRiskyAssets(assets) {
  const container = document.getElementById("dashboard-risky-assets");
  if (!container) return;
  if (assets.length === 0) {
    container.innerHTML = `<div style="color:#64748b;padding:1rem;">No asset risk data evaluated.</div>`;
    return;
  }

  let html = `<table class="siem-table">
    <thead><tr><th>Asset</th><th>Criticality</th><th>Risk Score</th></tr></thead>
    <tbody>`;
  assets.forEach(a => {
    let scoreColor = "#10b981";
    if (a.risk_score >= 80) scoreColor = "#ef4444";
    else if (a.risk_score >= 50) scoreColor = "#f97316";
    else if (a.risk_score >= 30) scoreColor = "#eab308";

    html += `<tr>
      <td><strong>${escapeHTML(a.name)}</strong><br><span class="mono" style="color:#94a3b8;">${escapeHTML(a.ip)}</span></td>
      <td><span class="badge badge-info">${escapeHTML(a.risk_level)}</span></td>
      <td><strong style="color:${scoreColor};font-size:1.05rem;">${a.risk_score}</strong>/100</td>
    </tr>`;
  });
  html += `</tbody></table>`;
  container.innerHTML = html;
}

function renderSuspiciousIPs(ips) {
  const container = document.getElementById("dashboard-top-ips");
  if (!container) return;
  if (ips.length === 0) {
    container.innerHTML = `<div style="color:#64748b;padding:1rem;">No suspicious IPs detected.</div>`;
    return;
  }
  let html = `<table class="siem-table">
    <thead><tr><th>Source IP</th><th>Alerts</th><th>Action</th></tr></thead>
    <tbody>`;
  ips.forEach(item => {
    html += `<tr>
      <td><span class="mono" style="color:#f87171;">${escapeHTML(item.ip)}</span></td>
      <td><span class="badge badge-critical">${item.count} Alerts</span></td>
      <td><a href="threat-intelligence.html?ip=${encodeURIComponent(item.ip)}" class="btn btn-outline" style="padding:0.2rem 0.5rem;font-size:0.75rem;">Intel</a></td>
    </tr>`;
  });
  html += `</tbody></table>`;
  container.innerHTML = html;
}

function renderTimeline(feed) {
  const container = document.getElementById("dashboard-activity-feed");
  if (!container) return;
  if (feed.length === 0) {
    container.innerHTML = `<div style="color:#64748b;padding:1rem;">No recent security activity logged.</div>`;
    return;
  }

  let html = "";
  feed.forEach(item => {
    const isCritical = item.severity === "CRITICAL";
    const itemClass = isCritical ? "item-critical" : (item.severity === "HIGH" ? "item-high" : "");
    html += `
      <div class="timeline-item ${itemClass}">
        <div class="timeline-time">${formatDate(item.timestamp)}</div>
        <div class="timeline-desc">
          <strong>${escapeHTML(item.title)}</strong>
          ${item.source_ip ? `<span class="mono" style="margin-left:6px;color:#94a3b8;">[${escapeHTML(item.source_ip)}]</span>` : ""}
        </div>
        <div>${formatSeverityBadge(item.severity)}</div>
      </div>
    `;
  });
  container.innerHTML = html;
}

