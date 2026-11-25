/**
 * MiniSIEM X Frontend Configuration & Shared Utilities
 */
const CONFIG = {
  API_BASE: "/api",
  APP_NAME: "MiniSIEM X",
  REFRESH_INTERVAL_MS: 10000
};

// Formatting utilities
function formatDate(isoString) {
  if (!isoString) return "-";
  try {
    const d = new Date(isoString);
    return d.toLocaleString("en-US", {
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false
    });
  } catch (e) {
    return isoString;
  }
}

function formatSeverityBadge(sev) {
  const s = (sev || "INFO").toUpperCase();
  let badgeClass = "badge-info";
  if (s === "CRITICAL") badgeClass = "badge-critical";
  else if (s === "HIGH") badgeClass = "badge-high";
  else if (s === "MEDIUM") badgeClass = "badge-medium";
  else if (s === "LOW") badgeClass = "badge-low";
  return `<span class="badge ${badgeClass}">${s}</span>`;
}

function formatStatusBadge(status) {
  const st = (status || "OPEN").toUpperCase();
  let badgeClass = "badge-info";
  if (st === "OPEN") badgeClass = "badge-critical";
  else if (st === "INVESTIGATING") badgeClass = "badge-high";
  else if (st === "RESOLVED") badgeClass = "badge-success";
  else if (st === "FALSE_POSITIVE") badgeClass = "badge-low";
  return `<span class="badge ${badgeClass}">${st}</span>`;
}

// Toast notification helper
function showToast(message, type = "info") {
  let container = document.getElementById("toast-container");
  if (!container) {
    container = document.createElement("div");
    container.id = "toast-container";
    container.className = "toast-container";
    document.body.appendChild(container);
  }

  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `<i class="fa-solid fa-circle-info"></i> ${message}`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = "0";
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// Helper to escape HTML to prevent XSS
function escapeHTML(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

