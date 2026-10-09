/* SentinelX API client.
   Change API_BASE if the backend runs somewhere other than localhost:8000. */
const API_BASE = window.SENTINELX_API_BASE || "http://localhost:8000";

const Auth = {
  getToken(){ return localStorage.getItem("sentinelx_token"); },
  setToken(t){ localStorage.setItem("sentinelx_token", t); },
  clear(){ localStorage.removeItem("sentinelx_token"); },
  isLoggedIn(){ return !!this.getToken(); },
};

async function apiRequest(path, { method = "GET", body = null, isForm = false, auth = true } = {}) {
  const headers = {};
  if (auth) {
    const token = Auth.getToken();
    if (token) headers["Authorization"] = `Bearer ${token}`;
  }
  let payload = body;
  if (body && !isForm) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }

  const res = await fetch(`${API_BASE}${path}`, { method, headers, body: payload });

  if (res.status === 401) {
    Auth.clear();
    if (!location.pathname.endsWith("index.html") && location.pathname !== "/") {
      window.location.href = "index.html";
    }
    throw new Error("Session expired. Please log in again.");
  }

  if (!res.ok) {
    let detail = `Request failed (${res.status})`;
    try {
      const errBody = await res.json();
      detail = errBody.detail || detail;
    } catch (_) {}
    throw new Error(detail);
  }

  if (res.status === 204) return null;

  const contentType = res.headers.get("content-type") || "";
  if (contentType.includes("application/json")) return res.json();
  return res;
}

const SentinelAPI = {
  register: (username, email, password) =>
    apiRequest("/auth/register", { method: "POST", body: { username, email, password }, auth: false }),

  login: async (username, password) => {
    const form = new URLSearchParams();
    form.append("username", username);
    form.append("password", password);
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form,
    });
    if (!res.ok) {
      let detail = "Invalid username or password";
      try { detail = (await res.json()).detail || detail; } catch (_) {}
      throw new Error(detail);
    }
    return res.json();
  },

  me: () => apiRequest("/auth/me"),

  listProjects: () => apiRequest("/projects"),
  createProject: (data) => apiRequest("/projects", { method: "POST", body: data }),
  getProject: (id) => apiRequest(`/projects/${id}`),
  deleteProject: (id) => apiRequest(`/projects/${id}`, { method: "DELETE" }),

  importScan: (projectId, file) => {
    const form = new FormData();
    form.append("file", file);
    return apiRequest(`/projects/${projectId}/import`, { method: "POST", body: form, isForm: true });
  },
  listScanReports: (projectId) => apiRequest(`/projects/${projectId}/reports`),

  listHosts: (projectId) => apiRequest(`/projects/${projectId}/hosts`),

  listVulnerabilities: (projectId, params = {}) => {
    const qs = new URLSearchParams(params).toString();
    return apiRequest(`/projects/${projectId}/vulnerabilities${qs ? "?" + qs : ""}`);
  },
  updateVulnerability: (id, data) => apiRequest(`/vulnerabilities/${id}`, { method: "PATCH", body: data }),

  dashboard: (projectId) => apiRequest(`/projects/${projectId}/dashboard`),

  aiExplain: (payload) => apiRequest("/ai/explain", { method: "POST", body: payload }),
  aiSummary: (projectId) => apiRequest("/ai/summary", { method: "POST", body: { project_id: projectId } }),

  generateReport: (projectId) => apiRequest(`/projects/${projectId}/generate-report`, { method: "POST" }),
  reportDownloadUrl: (projectId, filename) =>
    `${API_BASE}/projects/${projectId}/reports/download/${filename}`,
};
