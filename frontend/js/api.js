/**
 * MiniSIEM X Centralized API Client
 * Wraps Fetch with JWT Bearer Token, uniform error handling, and JSON parsing.
 */
async function apiFetch(endpoint, options = {}) {
  const url = endpoint.startsWith("http") ? endpoint : `${CONFIG.API_BASE}${endpoint}`;
  const token = localStorage.getItem("minisiemx_token");

  const headers = {
    ...options.headers
  };

  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  // If not FormData, default to application/json
  if (!(options.body instanceof FormData) && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }

  try {
    const res = await fetch(url, { ...options, headers });
    
    // Unauthorized handler
    if (res.status === 401 && !window.location.pathname.includes("login.html")) {
      localStorage.removeItem("minisiemx_token");
      localStorage.removeItem("minisiemx_user");
      window.location.href = "login.html";
      return null;
    }

    if (!res.ok) {
      let errorMsg = `API Error: ${res.status} ${res.statusText}`;
      try {
        const errData = await res.json();
        if (errData && errData.detail) {
          errorMsg = typeof errData.detail === "string" ? errData.detail : JSON.stringify(errData.detail);
        }
      } catch (e) {}
      throw new Error(errorMsg);
    }

    // Check if response is file download
    const contentType = res.headers.get("content-type");
    if (contentType && contentType.includes("text/csv")) {
      return await res.text();
    }

    return await res.json();
  } catch (err) {
    console.error(`Fetch failure [${url}]:`, err);
    throw err;
  }
}

