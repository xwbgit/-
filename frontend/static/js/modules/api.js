const API_BASE = '/api/v1';

export async function fetchWithTimeout(url, options, timeout = 5000) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeout);
    const response = await fetch(url, {
        ...options,
        signal: controller.signal
    });
    clearTimeout(id);
    return response;
}

export async function getHeartbeat() {
    return fetchWithTimeout(`${API_BASE}/heartbeat`, {}, 5000);
}

export async function getTokenStats() {
    return fetch(`${API_BASE}/reports/token-stats`);
}

export async function getTasks() {
    return fetch(`${API_BASE}/tasks`);
}

export async function launchScan(payload) {
    return fetch(`${API_BASE}/tasks`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
    });
}

export async function getTaskDetails(taskId) {
    return fetch(`${API_BASE}/tasks/${taskId}/details`);
}
