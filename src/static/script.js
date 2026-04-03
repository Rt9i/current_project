// ============================================================================
// Ransomware Protection System - Complete Clean Version
// ============================================================================

'use strict';
/* global Chart */

// ============================================================================
// SECTION 1: Configuration Constants
// ============================================================================

const API_BASE = '/api';
const API_TIMEOUT_MS = 8000;
const UPDATE_INTERVAL_MS = 5000;
const DEBUG_MODE = false;

// ============================================================================
// SECTION 2: Unicode-Safe Encoding Functions
// ============================================================================

function encodeBase64Unicode(str) {
    return btoa(
        encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, function(match, p1) {
            return String.fromCharCode('0x' + p1);
        })
    );
}

function decodeBase64Unicode(str) {
    return decodeURIComponent(
        Array.prototype.map.call(atob(str), function(c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join('')
    );
}

// ============================================================================
// SECTION 3: Helper Functions
// ============================================================================

function formatFileDate(timestamp) {
    if (!timestamp || timestamp === 0) {
        return 'N/A';
    }
    const date = new Date((timestamp || 0) * 1000);
    return date.toLocaleString('en-US', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
    });
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function getFileTypeDescription(ext) {
    const map = {
        'txt': 'Text File', 'doc': 'Word Document', 'docx': 'Word Document',
        'pdf': 'PDF Document', 'xls': 'Excel Spreadsheet', 'xlsx': 'Excel Spreadsheet',
        'ppt': 'PowerPoint', 'pptx': 'PowerPoint', 'jpg': 'Image', 'jpeg': 'Image',
        'png': 'Image', 'gif': 'Image', 'mp4': 'Video', 'avi': 'Video',
        'mp3': 'Audio', 'wav': 'Audio', 'zip': 'Archive', 'rar': 'Archive',
        'exe': 'Executable', 'dll': 'System File', 'py': 'Python Script',
        'js': 'JavaScript', 'html': 'Web Page', 'css': 'Style Sheet'
    };
    return map[ext] || 'File';
}

function normalizeWindowsPath(path) {
    if (!path) return path;
    let normalized = path.replace(/\//g, '\\');
    if (normalized.match(/^[A-Za-z]:[^\\]/)) {
        normalized = normalized.replace(/^([A-Za-z]:)/, '$1\\');
    }
    return normalized;
}

function debugLog(message, data = null) {
    if (DEBUG_MODE) {
        console.log(`[DEBUG] ${message}`, data || '');
    }
}

// ============================================================================
// SECTION 4: Application State
// ============================================================================

let systemStatus = 'offline';
let protectionActive = false;
let systemPaused = false;
let currentPage = 'dashboard';
let charts = {};

// ============================================================================
// SECTION 5: API Functions
// ============================================================================

async function fetchWithTimeout(url, options = {}, timeout = API_TIMEOUT_MS) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeout);
    options.signal = controller.signal;
    try {
        const resp = await fetch(url, options);
        clearTimeout(id);
        return resp;
    } catch (e) {
        clearTimeout(id);
        throw e;
    }
}

async function apiGet(path) {
    try {
        const r = await fetchWithTimeout(`${API_BASE}${path}`, { method: 'GET' });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return await r.json();
    } catch (error) {
        debugLog(`API GET error: ${path}`, error);
        throw error;
    }
}

async function apiPost(path, data) {
    try {
        const r = await fetchWithTimeout(`${API_BASE}${path}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
        });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return await r.json();
    } catch (error) {
        debugLog(`API POST error: ${path}`, error);
        throw error;
    }
}

// ============================================================================
// SECTION 6: UI Functions (Toast & Loading)
// ============================================================================

function showToast(message, type = 'info') {
    const toast = document.getElementById('toast');
    if (!toast) return;
    
    const toastIcon = toast.querySelector('.toast-icon');
    const toastMessage = toast.querySelector('.toast-message');
    
    switch (type) {
        case 'success': toastIcon.className = 'toast-icon fas fa-check-circle'; break;
        case 'error': toastIcon.className = 'toast-icon fas fa-exclamation-triangle'; break;
        case 'warning': toastIcon.className = 'toast-icon fas fa-exclamation-circle'; break;
        default: toastIcon.className = 'toast-icon fas fa-info-circle';
    }
    
    toastMessage.textContent = message;
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 3000);
}

function showToastSettings(message) {
    const toast = document.getElementById('toast-notification');
    const toastMessage = document.getElementById('toast-message-settings');
    if (!toast || !toastMessage) return;
    toastMessage.textContent = message;
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 3000);
}

function showLoading(show) {
    const overlay = document.getElementById('loadingOverlay');
    if (overlay) overlay.style.display = show ? 'flex' : 'none';
}

// ============================================================================
// SECTION 7: Protection Control Functions
// ============================================================================

async function onStartProtectionClicked() {
    showLoading(true);
    try {
        const r = await apiPost('/start', {});
        if (r?.success) {
            protectionActive = true;
            systemPaused = false;
        } else {
            showToast('Failed to start protection: ' + (r?.error || 'Unknown error'), 'error');
        }
    } catch (error) {
        showToast(`Error starting protection: ${error.message}`, 'error');
    }
    updateProtectionUI();
    showLoading(false);
}

async function onPauseProtectionClicked() {
    showLoading(true);
    try {
        const r = await apiPost('/pause', {});
        if (r?.success) {
            protectionActive = true;
            systemPaused = true;
        } else {
            showToast('Failed to pause protection: ' + (r?.error || 'Unknown error'), 'error');
        }
    } catch (error) {
        systemPaused = true;
        showToast(`Error pausing protection: ${error.message}`, 'error');
    }
    updateProtectionUI();
    showLoading(false);
}

async function onResumeProtectionClicked() {
    showLoading(true);
    try {
        const r = await apiPost('/resume', {});
        if (r?.success) {
            protectionActive = true;
            systemPaused = false;
        } else {
            showToast('Failed to resume protection: ' + (r?.error || 'Unknown error'), 'error');
        }
    } catch (error) {
        systemPaused = true;
        showToast(`Error resuming protection: ${error.message}`, 'error');
    }
    updateProtectionUI();
    showLoading(false);
}

async function onStopProtectionClicked() {
    showLoading(true);
    try {
        const r = await apiPost('/stop', {});
        if (r?.success) {
            protectionActive = false;
            systemPaused = false;
        } else {
            showToast('Failed to stop protection: ' + (r?.error || 'Unknown error'), 'error');
        }
    } catch (error) {
        protectionActive = false;
        systemPaused = false;
        showToast(`Error stopping protection: ${error.message}`, 'error');
    }
    updateProtectionUI();
    showLoading(false);
}

// ============================================================================
// SECTION 8: UI State Management
// ============================================================================

function updateProtectionUI() {
    const startBtn = document.getElementById('startProtection');
    const pauseBtn = document.getElementById('pauseProtection');
    const stopBtn = document.getElementById('stopProtection');
    const resumeBtn = document.getElementById('resumeProtection');
    const systemStatusEl = document.getElementById('systemStatus');
    
    if (protectionActive && !systemPaused) {
        if (startBtn) { startBtn.style.display = 'none'; startBtn.disabled = true; }
        if (pauseBtn) { pauseBtn.style.display = 'inline-flex'; pauseBtn.disabled = false; pauseBtn.textContent = 'Pause Monitoring'; }
        if (stopBtn) stopBtn.style.display = 'inline-flex'; stopBtn.disabled = false;
        if (resumeBtn) resumeBtn.style.display = 'none';
        if (systemStatusEl) systemStatusEl.innerHTML = '<span class="status-indicator online"></span><span>System Active</span>';
    } else if (protectionActive && systemPaused) {
        if (startBtn) startBtn.style.display = 'none';
        if (pauseBtn) pauseBtn.style.display = 'none';
        if (stopBtn) { stopBtn.style.display = 'inline-flex'; stopBtn.disabled = false; }
        if (resumeBtn) { resumeBtn.style.display = 'inline-flex'; resumeBtn.disabled = false; resumeBtn.textContent = 'Resume Monitoring'; }
        if (systemStatusEl) systemStatusEl.innerHTML = '<span class="status-indicator warning"></span><span>System Paused</span>';
    } else {
        if (startBtn) { startBtn.style.display = 'inline-flex'; startBtn.disabled = false; startBtn.textContent = 'Start Protection'; }
        if (pauseBtn) pauseBtn.style.display = 'none';
        if (stopBtn) stopBtn.style.display = 'none';
        if (resumeBtn) resumeBtn.style.display = 'none';
        if (systemStatusEl) systemStatusEl.innerHTML = '<span class="status-indicator offline"></span><span>System Stopped</span>';
    }
}

// ============================================================================
// SECTION 9: Navigation Functions
// ============================================================================

function navigateToPage(pageId) {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    const target = document.getElementById(pageId);
    if (target) {
        target.classList.add('active');
        currentPage = pageId;
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.toggle('active', item.dataset.page === pageId);
        });
        debugLog(`Navigated to page: ${pageId}`);
        switch (pageId) {
            case 'files': loadFilesData(); break;
            case 'alerts': loadAlertsData(); break;
            case 'recovery': loadRecoveryData(); break;
            case 'ai-status': loadAIData(); break;
            case 'settings': loadSettingsData(); break;
            case 'dashboard': 
                loadDashboardStats();
                loadBackupRestoreData();
                break;
        }
    }
}

function setupNavigationEventListeners() {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', () => {
            const pageId = item.dataset.page;
            if (pageId) navigateToPage(pageId);
        });
    });
}

// ============================================================================
// SECTION 10: Event Listeners Setup
// ============================================================================

function setupEventListeners() {
    const startBtn = document.getElementById('startProtection');
    const pauseBtn = document.getElementById('pauseProtection');
    const resumeBtn = document.getElementById('resumeProtection');
    const stopBtn = document.getElementById('stopProtection');
    
    if (startBtn) startBtn.onclick = onStartProtectionClicked;
    if (pauseBtn) pauseBtn.onclick = onPauseProtectionClicked;
    if (resumeBtn) resumeBtn.onclick = onResumeProtectionClicked;
    if (stopBtn) stopBtn.onclick = onStopProtectionClicked;
    
    const testAlertBtn = document.getElementById('testAlert');
    if (testAlertBtn) testAlertBtn.onclick = onTestAlertClicked;
    
    const browseFileToAnalyzeBtn = document.getElementById('browseFileToAnalyze');
    const browseLocalStoragePathBtn = document.getElementById('browseLocalStoragePath');
    const browseQuarantinePathBtn = document.getElementById('browseQuarantinePath');
    const browseMonitoredPathBtn = document.getElementById('browseMonitoredPath');
    
    if (browseFileToAnalyzeBtn) browseFileToAnalyzeBtn.onclick = onBrowseFileToAnalyzeClicked;
    if (browseLocalStoragePathBtn) browseLocalStoragePathBtn.onclick = onBrowseLocalStoragePathClicked;
    if (browseQuarantinePathBtn) browseQuarantinePathBtn.onclick = onBrowseQuarantinePathClicked;
    if (browseMonitoredPathBtn) browseMonitoredPathBtn.onclick = onBrowseMonitoredPathClicked;
    
    const analyzeFileBtn = document.getElementById('analyzeFile');
    if (analyzeFileBtn) analyzeFileBtn.onclick = onAnalyzeFileClicked;
    
    const connectGoogleDriveBtn = document.getElementById('connectGoogleDrive');
    const openGoogleDriveBtn = document.getElementById('openGoogleDrive');
    const disconnectGoogleDriveBtn = document.getElementById('disconnectGoogleDrive');
    
    if (connectGoogleDriveBtn) connectGoogleDriveBtn.onclick = onConnectGoogleDriveClicked;
    if (openGoogleDriveBtn) openGoogleDriveBtn.onclick = onOpenGoogleDriveClicked;
    if (disconnectGoogleDriveBtn) disconnectGoogleDriveBtn.onclick = onDisconnectGoogleDriveClicked;
    
    const refreshQuarantineBtn = document.getElementById('refreshQuarantine');
    const openLocalQuarantineBtn = document.getElementById('openLocalQuarantine');
    
    if (refreshQuarantineBtn) refreshQuarantineBtn.onclick = onRefreshQuarantineClicked;
    if (openLocalQuarantineBtn) openLocalQuarantineBtn.onclick = onOpenLocalQuarantineClicked;
    
    const reloadAIBtn = document.getElementById('reloadAI');
    if (reloadAIBtn) reloadAIBtn.onclick = onReloadAIClicked;
    
    const saveSettingsBtn = document.getElementById('saveSettings');
    const saveSettingsBtn2 = document.getElementById('save-settings-btn');
    
    if (saveSettingsBtn) saveSettingsBtn.onclick = onSaveSettingsClicked;
    if (saveSettingsBtn2) saveSettingsBtn2.onclick = onSaveSettingsClicked;
    
    const addLocalStoragePathBtn = document.getElementById('addLocalStoragePath');
    const addQuarantinePathBtn = document.getElementById('addQuarantinePath');
    const addMonitoredPathBtn = document.getElementById('addMonitoredPath');
    
    if (addLocalStoragePathBtn) addLocalStoragePathBtn.onclick = onAddLocalStoragePathClicked;
    if (addQuarantinePathBtn) addQuarantinePathBtn.onclick = onAddQuarantinePathClicked;
    if (addMonitoredPathBtn) addMonitoredPathBtn.onclick = onAddMonitoredPathClicked;
    
    const selectAllBtn = document.getElementById('select-all-btn');
    const deselectAllBtn = document.getElementById('deselect-all-btn');
    
    if (selectAllBtn) selectAllBtn.onclick = onSelectAllClicked;
    if (deselectAllBtn) deselectAllBtn.onclick = onDeselectAllClicked;
    
    document.querySelectorAll('.strategy-card').forEach(card => {
        card.addEventListener('click', () => {
            document.querySelectorAll('.strategy-card').forEach(c => c.classList.remove('selected'));
            card.classList.add('selected');
            onRecoveryStrategyChanged(card.dataset.strategy);
        });
    });
}

// ============================================================================
// SECTION 11: File Analysis Functions
// ============================================================================

async function onTestAlertClicked() {
    showLoading(true);
    try {
        const r = await apiPost('/test-alert', {});
    } catch (e) {
        showToast(`Error: ${e.message}`, 'error');
    }
    showLoading(false);
}

async function onBrowseFileClicked(callback) {
    try {
        const r = await apiPost('/browse-file', {});
        if (r?.success && callback) callback(r.path);
        else if (callback) callback(null);
    } catch (e) {
        if (callback) callback(null);
    }
}

function onBrowseFileToAnalyzeClicked() {
    onBrowseFileClicked(path => {
        const input = document.getElementById('filePathInput');
        if (input && path) {
            input.value = path;
        }
    });
}

async function onAnalyzeFileClicked() {
    const input = document.getElementById('filePathInput');
    const path = input?.value.trim();
    if (!path) return;
    showLoading(true);
    try {
        const r = await apiPost('/analyze-file', { file_path: path });
        if (r?.success) {
            showAnalysisResult(r.data);
        } else {
            showToast('File analysis failed: ' + (r?.error || 'Unknown error'), 'error');
        }
    } catch (e) {
        showToast(`Error: ${e.message}`, 'error');
    }
    showLoading(false);
}

function showAnalysisResult(data) {
    const el = document.getElementById('analysisResult');
    if (!el) return;
    const isThreat = data.is_threat || false;
    const threatLevel = data.threat_level || 'unknown';
    const confidence = data.confidence || 0;
    el.innerHTML = `
        <div class="analysis-result-content">
            <h4>Analysis Result</h4>
            <div class="result-item">
                <strong>Status:</strong> 
                <span class="${isThreat ? 'threat' : 'safe'}">${isThreat ? 'THREAT DETECTED' : 'SAFE'}</span>
            </div>
            <div class="result-item">
                <strong>Threat Level:</strong> ${threatLevel}
            </div>
            <div class="result-item">
                <strong>Confidence:</strong> ${confidence}%
            </div>
            ${data.file_info ? `<div class="result-item"><strong>File Info:</strong> ${JSON.stringify(data.file_info)}</div>` : ''}
        </div>
    `;
    el.style.display = 'block';
}

// ============================================================================
// SECTION 12: File Browsing Functions
// ============================================================================

async function onBrowseLocalStoragePathClicked() {
    try {
        const r = await apiPost('/browse-folder', {});
        if (r?.success && document.getElementById('localStoragePath')) {
            document.getElementById('localStoragePath').value = r.path;
        }
    } catch (e) {
        // Silent fail
    }
}

async function onBrowseQuarantinePathClicked() {
    try {
        const r = await apiPost('/browse-folder', {});
        if (r?.success && document.getElementById('quarantinePath')) {
            document.getElementById('quarantinePath').value = r.path;
        }
    } catch (e) {
        // Silent fail
    }
}

async function onBrowseMonitoredPathClicked() {
    try {
        const r = await apiPost('/browse-folder', {});
        if (r?.success && document.getElementById('newMonitoredPath')) {
            document.getElementById('newMonitoredPath').value = r.path;
        }
    } catch (e) {
        // Silent fail
    }
}

// ============================================================================
// SECTION 13: Google Drive Functions
// ============================================================================

async function onConnectGoogleDriveClicked() {
    showLoading(true);
    try {
        const r = await apiPost('/google-drive/connect', {});
        console.log('google-drive/connect response:', r);

        if (r?.success) {
            updateGoogleDriveUI('connected');
        } else {
            showToast(`Failed: ${r?.error || 'Unknown error'}`, 'error');
        }
    } catch (e) {
        console.error('Connect Google Drive error:', e);
        showToast(`Error: ${e.message}`, 'error');
    }
    showLoading(false);
}

function onOpenGoogleDriveClicked() {
    window.open('https://drive.google.com', '_blank');
}

async function onDisconnectGoogleDriveClicked() {
    showLoading(true);
    try {
        const r = await apiPost('/google-drive/disconnect', {});
        if (r?.success) {
            updateGoogleDriveUI('disconnected');
        } else {
            showToast('Failed to disconnect from Google Drive', 'error');
        }
    } catch (e) {
        showToast(`Error: ${e.message}`, 'error');
    }
    showLoading(false);
}

function updateGoogleDriveUI(status) {
    const driveStatus = document.getElementById('driveStatus');
    const connectBtn = document.getElementById('connectGoogleDrive');
    const openBtn = document.getElementById('openGoogleDrive');
    const disconnectBtn = document.getElementById('disconnectGoogleDrive');
    
    if (status === 'connected') {
        if (driveStatus) driveStatus.innerHTML = '<div class="status-indicator"><span class="status-dot online"></span><span>Connected</span></div>';
        if (connectBtn) connectBtn.style.display = 'none';
        if (openBtn) openBtn.style.display = 'inline-flex';
        if (disconnectBtn) disconnectBtn.style.display = 'inline-flex';
    } else {
        if (driveStatus) driveStatus.innerHTML = '<div class="status-indicator"><span class="status-dot offline"></span><span>Not Connected</span></div>';
        if (connectBtn) connectBtn.style.display = 'inline-flex';
        if (openBtn) openBtn.style.display = 'none';
        if (disconnectBtn) disconnectBtn.style.display = 'none';
    }
}

// ============================================================================
// SECTION 14: Quarantine Functions
// ============================================================================

async function onRefreshQuarantineClicked() {
    showLoading(true);
    try {
        const r = await apiGet('/quarantine');
        if (r?.success) {
            updateQuarantineList(r.data);
        } else {
            showToast('Failed to refresh quarantine list', 'error');
        }
    } catch (e) {
        showToast(`Error: ${e.message}`, 'error');
    }
    showLoading(false);
}

function onOpenLocalQuarantineClicked() {
    window.open('file:///C:/ProgramData/RansomwareProtection/quarantine', '_blank');
}

function updateQuarantineList(data) {
    const el = document.getElementById('quarantineList');
    if (!el) return;
    if (!data?.length) {
        el.innerHTML = '<p>No quarantined files found.</p>';
        return;
    }
    el.innerHTML = data.map(item => `
        <div class="quarantine-item">
            <div class="item-info">
                <strong>${item.filename || item.qname}</strong>
                <p>Path: ${item.path || item.file_path}</p>
                <p>Date: ${item.created_at || item.date || 'Unknown'}</p>
                <p>Threat: ${item.threat_type || 'Unknown'}</p>
            </div>
            <div class="item-actions">
                <button class="btn btn-sm btn-danger" onclick="removeFromQuarantine('${item.qname}')">
                    <i class="fas fa-trash"></i> Remove
                </button>
                <button class="btn btn-sm btn-info" onclick="restoreFromQuarantine('${item.qname}')">
                    <i class="fas fa-undo"></i> Restore
                </button>
            </div>
        </div>
    `).join('');
}

function removeFromQuarantine(qname) {
    if (!qname) return;
    showLoading(true);
    apiPost('/quarantine/delete', { qname })
        .then(r => {
            if (r?.success) {
                onRefreshQuarantineClicked();
            } else {
                showToast('Failed to remove file', 'error');
            }
        })
        .catch(e => {
            showToast(`Error: ${e.message}`, 'error');
        })
        .finally(() => showLoading(false));
}

function restoreFromQuarantine(qname) {
    if (!qname) return;
    showLoading(true);
    apiPost('/quarantine/restore', { qname })
        .then(r => {
            if (r?.success) {
                onRefreshQuarantineClicked();
            } else {
                showToast('Failed to restore file', 'error');
            }
        })
        .catch(e => {
            showToast(`Error: ${e.message}`, 'error');
        })
        .finally(() => showLoading(false));
}

// ============================================================================
// SECTION 15: AI Functions
// ============================================================================

async function onReloadAIClicked() {
    showLoading(true);
    try {
        const r = await apiPost('/ai/reload', {});
        if (r?.success) {
            loadAIData();
        } else {
            showToast('Failed to reload AI model', 'error');
        }
    } catch (e) {
        showToast(`Error: ${e.message}`, 'error');
    }
    showLoading(false);
}

async function loadAIData() {
    try {
        const r = await apiGet('/ai/status');
        if (r?.success) updateAIDisplay(r.data);
    } catch (e) {
        debugLog('Error loading AI ', e);
    }
}

function updateAIDisplay(data) {
    const el = document.getElementById('aiDetails');
    if (!el) return;
    el.innerHTML = `
        <div class="ai-model-info">
            <h3>AI Model Status</h3>
            <div class="model-stats">
                <div class="stat"><strong>Model Type:</strong> ${data.model_type || 'Unknown'}</div>
                <div class="stat"><strong>Status:</strong> <span class="${data.status === 'active' ? 'success' : 'warning'}">${data.status || 'Unknown'}</span></div>
                <div class="stat"><strong>Accuracy:</strong> ${data.accuracy || 0}%</div>
                <div class="stat"><strong>Last Update:</strong> ${data.last_update || 'Never'}</div>
                <div class="stat"><strong>Files Scanned:</strong> ${data.files_scanned || 0}</div>
                <div class="stat"><strong>Threats Detected:</strong> ${data.threats_detected || 0}</div>
            </div>
        </div>
    `;
}

// ============================================================================
// SECTION 16: Settings Functions
// ============================================================================

async function onSaveSettingsClicked() {
    showLoading(true);
    try {
        const settings = collectSettings();
        const r = await apiPost('/settings', settings);
        if (r?.success) {
            showToastSettings('Settings saved successfully!');
        } else {
            showToast('Failed to save settings', 'error');
        }
    } catch (e) {
        showToast(`Error: ${e.message}`, 'error');
    }
    showLoading(false);
}

function collectSettings() {
    return {
        protection: {
            real_time: document.getElementById('realTimeProtection')?.checked || false,
            auto_quarantine: document.getElementById('autoQuarantine')?.checked || false,
            scan_on_access: document.getElementById('scanOnAccess')?.checked || false,
            scan_schedule: document.getElementById('scanSchedule')?.value || 'daily'
        },
        alerts: {
            enabled: document.getElementById('enableAlerts')?.checked || false,
            level: document.getElementById('alertLevel')?.value || 'medium',
            email_notifications: document.getElementById('emailNotifications')?.checked || false,
            sound_alerts: document.getElementById('soundAlerts')?.checked || false
        },
        storage: {
            local_path: document.getElementById('localStoragePath')?.value || 'C:\\ProgramData\\RansomwareProtection\\backups',
            quarantine_path: document.getElementById('quarantinePath')?.value || 'C:\\ProgramData\\RansomwareProtection\\quarantine'
        }
    };
}

async function loadSettingsData() {
    try {
        const r = await apiGet('/settings');
        if (r?.success) updateSettingsDisplay(r.data);
    } catch (e) {
        debugLog('Error loading settings:', e);
    }
}

function updateSettingsDisplay(data) {
    if (data.protection) {
        if (document.getElementById('realTimeProtection')) document.getElementById('realTimeProtection').checked = data.protection.real_time;
        if (document.getElementById('autoQuarantine')) document.getElementById('autoQuarantine').checked = data.protection.auto_quarantine;
        if (document.getElementById('scanOnAccess')) document.getElementById('scanOnAccess').checked = data.protection.scan_on_access;
        if (document.getElementById('scanSchedule')) document.getElementById('scanSchedule').value = data.protection.scan_schedule;
    }
    if (data.alerts) {
        if (document.getElementById('enableAlerts')) document.getElementById('enableAlerts').checked = data.alerts.enabled;
        if (document.getElementById('alertLevel')) document.getElementById('alertLevel').value = data.alerts.level;
        if (document.getElementById('emailNotifications')) document.getElementById('emailNotifications').checked = data.alerts.email_notifications;
        if (document.getElementById('soundAlerts')) document.getElementById('soundAlerts').checked = data.alerts.sound_alerts;
    }
    if (data.storage) {
        if (document.getElementById('localStoragePath')) document.getElementById('localStoragePath').value = data.storage.local_path;
        if (document.getElementById('quarantinePath')) document.getElementById('quarantinePath').value = data.storage.quarantine_path;
    }
}

// ============================================================================
// SECTION 17: Path Management Functions
// ============================================================================

async function onAddLocalStoragePathClicked() {
    const path = document.getElementById('localStoragePath')?.value.trim();
    if (!path) return;
    try {
        const r = await apiPost('/settings/paths/local', { path });
        if (r?.success) {
            loadSettingsData();
        }
    } catch (e) {
        showToast(`Error: ${e.message}`, 'error');
    }
}

async function onAddQuarantinePathClicked() {
    const path = document.getElementById('quarantinePath')?.value.trim();
    if (!path) return;
    try {
        const r = await apiPost('/settings/paths/quarantine', { path });
        if (r?.success) {
            loadSettingsData();
        }
    } catch (e) {
        showToast(`Error: ${e.message}`, 'error');
    }
}

async function onAddMonitoredPathClicked() {
    const path = document.getElementById('newMonitoredPath')?.value.trim();
    if (!path) return;
    try {
        const r = await apiPost('/settings/paths/monitored', { path });
        if (r?.success) {
            document.getElementById('newMonitoredPath').value = '';
            loadMonitoredPaths();
            loadFilesForSelectedPath();
        }
    } catch (e) {
        showToast(`Error: ${e.message}`, 'error');
    }
}

async function loadMonitoredPaths() {
    try {
        const r = await apiGet('/settings/paths/monitored');
        const paths = r?.success ? r.paths : [];
        const container = document.getElementById('monitoredPaths');
        if (!container) return;

        container.innerHTML = '';
        if (paths.length === 0) {
            container.innerHTML = '<p class="no-paths">No monitored paths configured.</p>';
            return;
        }

        paths.forEach((path, index) => {
            const item = document.createElement('div');
            item.className = 'monitored-path-item';
            
            const pathInfo = document.createElement('div');
            pathInfo.className = 'path-info';
            
            const pathText = document.createElement('span');
            pathText.className = 'path-text';
            pathText.textContent = path;
            
            const statusTag = document.createElement('span');
            statusTag.className = 'status-tag status-active';
            statusTag.textContent = 'Active';
            
            pathInfo.appendChild(pathText);
            pathInfo.appendChild(statusTag);
            
            const pathActions = document.createElement('div');
            pathActions.className = 'path-actions';
            
            const viewBtn = document.createElement('button');
            viewBtn.className = 'btn btn-sm btn-info';
            viewBtn.innerHTML = '<i class="fas fa-eye"></i> View Files';
            viewBtn.onclick = () => loadFilesForPath(path);
            
            const removeBtn = document.createElement('button');
            removeBtn.className = 'btn btn-sm btn-danger';
            removeBtn.innerHTML = '<i class="fas fa-trash"></i> Remove';
            removeBtn.onclick = () => removeMonitoredPath(path);
            
            pathActions.appendChild(viewBtn);
            pathActions.appendChild(removeBtn);
            
            item.appendChild(pathInfo);
            item.appendChild(pathActions);
            
            container.appendChild(item);
        });
    } catch (e) {
        debugLog('Error loading monitored paths:', e);
    }
}

async function removeMonitoredPath(path) {
    try {
        if (!path || typeof path !== 'string') {
            return;
        }
        
        if (path.includes('ran5\\current_project\\')) {
            loadMonitoredPaths();
            return;
        }
        
        const encoded = encodeBase64Unicode(path);
        const r = await apiPost(`/settings/paths/monitored/${encoded}`, {});
        if (r?.success) {
            loadMonitoredPaths();
            loadFilesForSelectedPath();
        }
    } catch (e) {
        showToast(`Error: ${e.message}`, 'error');
    }
}

// ============================================================================
// SECTION 18: File Selection UI
// ============================================================================

function onSelectAllClicked() {
    document.querySelectorAll('#filesTableBody input[type="checkbox"]').forEach(cb => cb.checked = true);
}

function onDeselectAllClicked() {
    document.querySelectorAll('#filesTableBody input[type="checkbox"]').forEach(cb => cb.checked = false);
}

// ============================================================================
// SECTION 19: Data Loading Functions
// ============================================================================

async function initializeSystem() {
    try {
        await Promise.all([
            loadDashboardStats(),
            loadFilesData(),
            loadAlertsData(),
            loadRecoveryData()
        ]);
        const status = await apiGet('/status');
        if (status?.success) {
            systemStatus = status.data.status || 'offline';
            protectionActive = status.data.protection_active || false;
            systemPaused = status.data.system_paused || false;
        }
        updateProtectionUI();
    } catch (e) {
        debugLog('System init error:', e);
        systemStatus = 'offline';
    }
}

async function loadDashboardStats() {
    try {
        const r = await apiGet('/stats');
        if (r?.success) {
            const s = r.data;
            if (document.getElementById('safeFiles')) document.getElementById('safeFiles').textContent = s.safe_files || 0;
            if (document.getElementById('infectedFiles')) document.getElementById('infectedFiles').textContent = s.infected_files || 0;
            if (document.getElementById('quarantinedFiles')) document.getElementById('quarantinedFiles').textContent = s.quarantined_files || 0;
            if (document.getElementById('detectedAttacks')) document.getElementById('detectedAttacks').textContent = s.detected_attacks || 0;
        }
        
        const pathsRes = await apiGet('/settings/paths/monitored');
        if (pathsRes?.success && pathsRes.paths?.length) {
            const firstPath = pathsRes.paths[0];
            const encoded = encodeBase64Unicode(firstPath);
            const filesRes = await apiGet(`/list-files?path=${encoded}`);
            if (filesRes?.success) {
                updateRecentFilesTable(filesRes.files.slice(0, 10));
            } else {
                updateRecentFilesTable([]);
            }
        } else {
            updateRecentFilesTable([]);
        }
    } catch (e) {
        debugLog('Error loading stats or files:', e);
        updateRecentFilesTable([]);
    }
}

function updateRecentFilesTable(files) {
    const tbody = document.getElementById('recent-files-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    if (!files?.length) {
        tbody.innerHTML = `<tr><td colspan="5">No recent files</td></tr>`;
        return;
    }
    files.slice(0, 10).forEach(file => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${file.name}</td>
            <td><span class="status-safe">Safe</span></td>
            <td>${formatFileDate(file.modified)}</td>
            <td>${file.ai_confidence ? file.ai_confidence + '%' : 'N/A'}</td>
            <td>${file.sha256 || 'N/A'}</td>
        `;
        tbody.appendChild(row);
    });
}

async function loadFilesData() {
    try {
        const r = await apiGet('/files');
        if (r?.success) updateFilesDisplay(r.data);
    } catch (e) {
        debugLog('Error loading files:', e);
    }
}

function updateFilesDisplay(data) {
    // Display moved to updateRecentFilesTable
}

async function loadAlertsData() {
    try {
        const r = await apiGet('/alerts');
        if (r?.success) updateAlertsBadge(r.data);
    } catch (e) {
        debugLog('Error loading alerts:', e);
    }
}

function updateAlertsBadge(data) {
    const badge = document.getElementById('alertsBadge');
    if (!badge || !data) return;
    badge.textContent = data.alert_count || 0;
    if (data.high_priority > 0) badge.className = 'badge danger';
    else if (data.alert_count > 0) badge.className = 'badge warning';
    else badge.className = 'badge';
}

async function loadRecoveryData() {
    try {
        const r = await apiGet('/recovery');
        if (r?.success) {
            const statusEl = document.querySelector('.backup-status');
            if (statusEl && r.data?.backup_status) {
                statusEl.textContent = `Backup: ${r.data.backup_status}`;
            }
        }
    } catch (e) {
        debugLog('Error loading recovery:', e);
    }
}

// ============================================================================
// SECTION 20: Backup & Restore Functions
// ============================================================================

async function loadBackupRestoreData() {
    try {
        const r = await apiGet('/backup/list');
        if (r?.success) {
            updateBackupRestoreTable(r.data?.backups || []);
        } else {
            updateBackupRestoreTable([]);
        }
    } catch (e) {
        debugLog('Error loading backup list:', e);
        updateBackupRestoreTable([]);
    }
}

function updateBackupRestoreTable(backups) {
    const tbody = document.getElementById('backup-restore-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    if (!backups.length) {
        tbody.innerHTML = '<tr><td colspan="5">No backups found</td></tr>';
        return;
    }
    backups.forEach(backup => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${backup.filename || backup.id || 'Unknown'}</td>
            <td>${backup.path || 'N/A'}<br/>${formatFileDate(backup.timestamp)}</td>
            <td>${backup.sha256 || 'N/A'}</td>
            <td><span class="status-safe">Backed Up</span></td>
            <td>
                <button class="btn btn-sm btn-info" onclick="restoreBackup('${backup.id || backup.filename}')">
                    <i class="fas fa-undo"></i> Restore
                </button>
            </td>
        `;
        tbody.appendChild(row);
    });
}

function restoreBackup(backupId) {
    showLoading(true);
    apiPost('/backup/restore', { backup_id: backupId })
        .then(r => {
            if (r?.success) {
                loadBackupRestoreData();
            } else {
                showToast('Failed to restore backup', 'error');
            }
        })
        .catch(e => {
            showToast(`Error: ${e.message}`, 'error');
        })
        .finally(() => showLoading(false));
}

// ============================================================================
// SECTION 21: Charts Functions - Attack Timeline
// ============================================================================

function initializeCharts() {
    // Attack Timeline - Multi-line Spline Area Chart
    const attackCtx = document.getElementById('attackChart');
    if (attackCtx) {
        const labels = ['15:30', '15:31', '15:32', '15:33', '15:34', '15:35'];
        const analysisData = [1, 1, 1, 0.5, 0, 0];
        const suspiciousData = [0, 1, 0.5, 0, 0, 0];
        const cleanData = [0, 0.5, 1, 0.5, 0, 0];
        
        charts.attack = new Chart(attackCtx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'Files Analyzed',
                        data: analysisData,
                        borderColor: 'rgb(239, 68, 68)',
                        backgroundColor: 'rgba(239, 68, 68, 0.2)',
                        borderWidth: 3,
                        tension: 0.4,
                        fill: true,
                        pointRadius: 6,
                        pointHoverRadius: 8
                    },
                    {
                        label: 'Suspicious Files',
                        data: suspiciousData,
                        borderColor: 'rgb(245, 158, 11)',
                        backgroundColor: 'rgba(245, 158, 11, 0.2)',
                        borderWidth: 3,
                        tension: 0.4,
                        fill: true,
                        pointRadius: 6,
                        pointHoverRadius: 8
                    },
                    {
                        label: 'Clean Files',
                        data: cleanData,
                        borderColor: 'rgb(16, 185, 129)',
                        backgroundColor: 'rgba(16, 185, 129, 0.2)',
                        borderWidth: 3,
                        tension: 0.4,
                        fill: true,
                        pointRadius: 6,
                        pointHoverRadius: 8
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { mode: 'index', intersect: false },
                plugins: {
                    legend: {
                        position: 'top',
                        labels: {
                            usePointStyle: true,
                            padding: 20,
                            font: { size: 12, weight: '500' },
                            color: '#374151'
                        }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(0, 0, 0, 0.75)',
                        titleFont: { size: 13, weight: 'bold' },
                        bodyFont: { size: 12 },
                        padding: 10,
                        cornerRadius: 6
                    }
                },
                scales: {
                    x: {
                        grid: { display: true, color: 'rgba(0, 0, 0, 0.05)' },
                        ticks: { font: { size: 11, weight: '500' }, color: '#6b7280' }
                    },
                    y: {
                        beginAtZero: true,
                        max: 1.2,
                        grid: { color: 'rgba(0, 0, 0, 0.05)' },
                        ticks: { font: { size: 11 }, color: '#6b7280', stepSize: 0.2 }
                    }
                }
            }
        });
    }
    
    // File Status Pie Chart (if exists)
    const fileStatusCtx = document.getElementById('fileStatusChart');
    if (fileStatusCtx) {
        charts.fileStatus = new Chart(fileStatusCtx, {
            type: 'doughnut',
            data: {
                labels: ['Safe Files', 'Suspicious Files', 'Threats'],
                datasets: [{
                    data: [75, 18, 7],
                    backgroundColor: ['rgb(16, 185, 129)', 'rgb(245, 158, 11)', 'rgb(239, 68, 68)'],
                    borderWidth: 0,
                    hoverOffset: 8
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '65%',
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { usePointStyle: true, padding: 15, font: { size: 11 } }
                    }
                }
            }
        });
    }
}

// ============================================================================
// SECTION 22: Recovery Strategy Functions
// ============================================================================

async function onRecoveryStrategyChanged(strategy) {
    try {
        const r = await apiPost('/recovery/strategy', { strategy });
        if (!r?.success) {
            showToast('Failed to update strategy', 'error');
        }
    } catch (e) {
        showToast(`Error: ${e.message}`, 'error');
    }
}

// ============================================================================
// SECTION 23: File Listing Functions
// ============================================================================

async function loadFilesForPath(path) {
    showLoading(true);
    try {
        const encoded = encodeBase64Unicode(path);
        const r = await apiGet(`/list-files?path=${encoded}`);
        if (r?.success) {
            displayFilesInTable(r.files);
            const section = document.querySelector('.files-display-section');
            if (section) section.style.display = 'block';
        } else {
            displayFilesInTable([]);
        }
    } catch (e) {
        showToast(`Error: ${e.message}`, 'error');
        displayFilesInTable([]);
    }
    showLoading(false);
}

function displayFilesInTable(files) {
    const tbody = document.getElementById('filesTableBody');
    if (!tbody) return;
    tbody.innerHTML = '';
    if (!files?.length) {
        tbody.innerHTML = '<tr><td colspan="5">No files found in selected path</td></tr>';
        return;
    }
    files.forEach(file => {
        const ext = file.name.split('.').pop()?.toLowerCase() || '';
        const type = getFileTypeDescription(ext);
        const size = formatFileSize(file.size);
        const date = formatFileDate(file.modified);
        const row = document.createElement('tr');
        row.innerHTML = `
            <td><input type="checkbox" class="file-checkbox" data-file-path="${file.path.replace(/"/g, '&quot;')}"></td>
            <td>${file.name}</td>
            <td>${date}</td>
            <td>${type}</td>
            <td>${size}</td>
        `;
        row.addEventListener('click', e => {
            if (!e.target.closest('input[type="checkbox"]')) {
                const cb = row.querySelector('input[type="checkbox"]');
                cb.checked = !cb.checked;
            }
        });
        tbody.appendChild(row);
    });
}

async function loadFilesForSelectedPath() {
    try {
        const r = await apiGet('/settings/paths/monitored');
        const paths = r?.success ? r.paths : [];
        if (paths.length > 0) await loadFilesForPath(paths[0]);
    } catch (e) {
        debugLog('Error loading first path files:', e);
    }
}

// ============================================================================
// SECTION 24: Application Startup
// ============================================================================

document.addEventListener('DOMContentLoaded', async () => {
    initializeCharts();
    setupEventListeners();
    setupNavigationEventListeners();
    await initializeSystem();
    loadMonitoredPaths();
    
    setInterval(async () => {
        try {
            const r = await apiGet('/status');
            if (r?.success) {
                protectionActive = r.data.protection_active || false;
                systemPaused = r.data.system_paused || false;
                updateProtectionUI();
            }
        } catch (e) {
            debugLog('Periodic status check failed:', e);
        }
    }, 10000);
});



window.startProtection = onStartProtectionClicked;
window.pauseProtection = onPauseProtectionClicked;
window.resumeProtection = onResumeProtectionClicked;
window.stopProtection = onStopProtectionClicked;
window.updateProtectionUI = updateProtectionUI;
window.navigateToPage = navigateToPage;
window.debugLog = debugLog;
window.showToast = showToast;
window.loadFilesForPath = loadFilesForPath;
window.removeMonitoredPath = removeMonitoredPath;
window.removeFromQuarantine = removeFromQuarantine;
window.restoreFromQuarantine = restoreFromQuarantine;
window.restoreBackup = restoreBackup;

