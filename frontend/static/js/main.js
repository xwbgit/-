import { getHeartbeat, getTokenStats } from './modules/api.js';

window._dualPaneCache = window._dualPaneCache || {};

// 暴露为全局以便内联 onclick 调用（平滑过渡期间使用）
window.showDualPaneModal = function(reqJson, resJson) {
    const modal = document.getElementById('dual-pane-modal');
    if (!modal) return;
    
    document.getElementById('raw-request-view').innerText = typeof reqJson === 'string' ? reqJson : JSON.stringify(reqJson, null, 2);
    document.getElementById('raw-response-view').innerText = typeof resJson === 'string' ? resJson : JSON.stringify(resJson, null, 2);
    
    modal.style.display = 'flex';
};

window.showDualPaneModalById = function(key) {
    const data = window._dualPaneCache[key];
    if (data) {
        window.showDualPaneModal(data.req, data.res);
    }
};
