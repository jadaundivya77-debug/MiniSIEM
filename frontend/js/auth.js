/**
 * MiniSIEM X Authentication & Session Management
 */
function checkAuth() {
  const token = localStorage.getItem("minisiemx_token");
  if (!token) {
    window.location.href = "login.html";
    return null;
  }
  const user = JSON.parse(localStorage.getItem("minisiemx_user") || "{}");
  updateUserUI(user);
  return user;
}

function updateUserUI(user) {
  const userBadge = document.getElementById("topbar-user-badge");
  if (userBadge) {
    userBadge.innerHTML = `
      <i class="fa-solid fa-user-shield"></i>
      <span>${escapeHTML(user.username || "Analyst")} (${escapeHTML(user.role || "SOC")})</span>
    `;
  }
}

async function handleLogin(username, password) {
  try {
    const data = await apiFetch("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password })
    });

    if (data && data.access_token) {
      localStorage.setItem("minisiemx_token", data.access_token);
      localStorage.setItem("minisiemx_user", JSON.stringify(data.user));
      showToast(`Welcome back, ${data.user.username}!`, "success");
      setTimeout(() => {
        window.location.href = "dashboard.html";
      }, 500);
    }
  } catch (err) {
    showToast(err.message || "Authentication failed. Check credentials.", "danger");
  }
}

function handleLogout() {
  localStorage.removeItem("minisiemx_token");
  localStorage.removeItem("minisiemx_user");
  window.location.href = "login.html";
}

// Quick Fill helper on Login page
function quickFillLogin(user, pass) {
  const uInput = document.getElementById("username");
  const pInput = document.getElementById("password");
  if (uInput && pInput) {
    uInput.value = user;
    pInput.value = pass;
    uInput.focus();
  }
}

