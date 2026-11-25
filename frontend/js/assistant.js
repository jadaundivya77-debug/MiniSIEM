/**
 * MiniSIEM X AI Security Assistant & Simulation Controller
 * Provides interactive SOC assistant drawer and controlled attack simulations.
 */

// Toggle Assistant Drawer
function toggleAssistant() {
  const drawer = document.getElementById("assistant-drawer");
  if (drawer) {
    drawer.classList.toggle("open");
    if (drawer.classList.contains("open")) {
      document.getElementById("assistant-input")?.focus();
    }
  }
}

// Send Query to AI Security Assistant
async function sendAssistantMessage(customQuery = null, contextType = null, contextId = null) {
  const input = document.getElementById("assistant-input");
  const message = customQuery || (input ? input.value.trim() : "");
  if (!message) return;

  const chatContainer = document.getElementById("assistant-chat");
  if (!chatContainer) return;

  // Add User bubble
  const userBubble = document.createElement("div");
  userBubble.className = "chat-bubble chat-bubble-user";
  userBubble.innerHTML = escapeHTML(message);
  chatContainer.appendChild(userBubble);

  if (input) input.value = "";
  chatContainer.scrollTop = chatContainer.scrollHeight;

  // Loading state
  const loadingBubble = document.createElement("div");
  loadingBubble.className = "chat-bubble chat-bubble-assistant";
  loadingBubble.id = "assistant-loading";
  loadingBubble.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Analyzing telemetry & MITRE playbooks...`;
  chatContainer.appendChild(loadingBubble);
  chatContainer.scrollTop = chatContainer.scrollHeight;

  try {
    const res = await apiFetch("/assistant/chat", {
      method: "POST",
      body: JSON.stringify({
        message: message,
        context_type: contextType,
        context_id: contextId
      })
    });

    document.getElementById("assistant-loading")?.remove();

    const assistantBubble = document.createElement("div");
    assistantBubble.className = "chat-bubble chat-bubble-assistant";
    
    // Parse markdown-style bold and lists for display
    let formattedReply = escapeHTML(res.reply)
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/### (.*?)\n/g, '<h4 style="color:#38bdf8;margin:6px 0;">$1</h4>')
      .replace(/• (.*?)\n/g, '<li>$1</li>')
      .replace(/\n\n/g, '<br><br>');

    assistantBubble.innerHTML = formattedReply;
    chatContainer.appendChild(assistantBubble);
    chatContainer.scrollTop = chatContainer.scrollHeight;

  } catch (err) {
    document.getElementById("assistant-loading")?.remove();
    const errBubble = document.createElement("div");
    errBubble.className = "chat-bubble chat-bubble-assistant";
    errBubble.style.color = "#ef4444";
    errBubble.innerText = "Error consulting Security Assistant: " + err.message;
    chatContainer.appendChild(errBubble);
  }
}

// Open Simulation Modal
function openSimulationModal() {
  const modal = document.getElementById("simulation-modal");
  if (modal) modal.classList.add("active");
}

function closeSimulationModal() {
  const modal = document.getElementById("simulation-modal");
  if (modal) modal.classList.remove("active");
}

// Trigger Synthetic Attack Scenario
async function triggerSimulation(scenario) {
  showToast(`Initiating simulation scenario: '${scenario}'...`, "info");
  closeSimulationModal();

  try {
    const res = await apiFetch("/simulation/start", {
      method: "POST",
      body: JSON.stringify({ scenario: scenario })
    });

    showToast(
      `Simulation Complete! Generated ${res.events_generated} logs, ${res.alerts_generated} alerts, ${res.incidents_generated} incidents.`, 
      "success"
    );

    // Refresh current view if functions exist
    if (typeof loadDashboardStats === "function") loadDashboardStats();
    if (typeof loadAlerts === "function") loadAlerts();
    if (typeof loadIncidents === "function") loadIncidents();
    if (typeof loadLogs === "function") loadLogs();
  } catch (err) {
    showToast("Simulation error: " + err.message, "danger");
  }
}

// Reset Demo Data
async function resetSimulationData() {
  if (!confirm("Are you sure you want to purge all simulated demo telemetry, alerts, and incidents? Real logs will be preserved.")) {
    return;
  }
  try {
    const res = await apiFetch("/simulation/reset", { method: "POST" });
    showToast(res.message, "success");
    closeSimulationModal();

    if (typeof loadDashboardStats === "function") loadDashboardStats();
    if (typeof loadAlerts === "function") loadAlerts();
    if (typeof loadIncidents === "function") loadIncidents();
    if (typeof loadLogs === "function") loadLogs();
  } catch (err) {
    showToast("Failed to reset demo data: " + err.message, "danger");
  }
}

