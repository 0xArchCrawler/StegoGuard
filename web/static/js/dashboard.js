/**
 * StegoGuard Professional Dashboard - Main JavaScript
 * WebSocket-powered real-time steganography analysis interface
 */

// ============================================================================
// GLOBAL STATE
// ============================================================================

const state = {
    socket: null,
    currentTheme: 'dark-ops',
    currentTab: 'scan',
    activeAnalysis: null,
    analysisHistory: [],
    systemMetrics: {},
    isConnected: false
};

// ============================================================================
// INITIALIZATION
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
    initializeWebSocket();
    initializeThemeSwitcher();
    initializeNavigation();
    initializeUpload();
    loadSystemMetrics();
    loadAnalysisHistory();
    startMetricsPolling();
});

// ============================================================================
// WEBSOCKET CONNECTION
// ============================================================================

function initializeWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;

    state.socket = io(wsUrl, {
        transports: ['websocket', 'polling'],
        reconnection: true,
        reconnectionDelay: 1000,
        reconnectionAttempts: 5
    });

    state.socket.on('connect', handleSocketConnect);
    state.socket.on('disconnect', handleSocketDisconnect);
    state.socket.on('analysis_progress', handleAnalysisProgress);
    state.socket.on('analysis_complete', handleAnalysisComplete);
    state.socket.on('analysis_error', handleAnalysisError);
    state.socket.on('system_metrics', handleSystemMetrics);
}

function handleSocketConnect() {
    state.isConnected = true;
    showNotification('Connected to StegoGuard server', 'success');
    updateConnectionStatus(true);
}

function handleSocketDisconnect() {
    state.isConnected = false;
    showNotification('Disconnected from server', 'warning');
    updateConnectionStatus(false);
}

function handleAnalysisProgress(data) {
    updateProgressBar(data.progress, data.message);
}

function handleAnalysisComplete(data) {
    state.activeAnalysis = data;
    displayResults(data);
    addToHistory(data);
    hideProgressBar();
    showNotification('Analysis complete', 'success');
}

function handleAnalysisError(data) {
    hideProgressBar();
    showNotification(`Analysis failed: ${data.error}`, 'danger');
}

function handleSystemMetrics(data) {
    state.systemMetrics = data;
    updateSystemMetrics(data);
}

// ============================================================================
// THEME SWITCHER
// ============================================================================

function initializeThemeSwitcher() {
    const themeButtons = document.querySelectorAll('.theme-btn');

    themeButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const theme = btn.dataset.theme;
            switchTheme(theme);
        });
    });

    // Load saved theme
    const savedTheme = localStorage.getItem('stegoguard-theme') || 'dark-ops';
    switchTheme(savedTheme);
}

function switchTheme(theme) {
    // Remove all theme classes
    document.body.className = document.body.className
        .split(' ')
        .filter(c => !c.startsWith('theme-'))
        .join(' ');

    // Add new theme
    document.body.classList.add(`theme-${theme}`);

    // Update active button
    document.querySelectorAll('.theme-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.theme === theme);
    });

    // Save preference
    state.currentTheme = theme;
    localStorage.setItem('stegoguard-theme', theme);
}

// ============================================================================
// NAVIGATION
// ============================================================================

function initializeNavigation() {
    const navTabs = document.querySelectorAll('.nav-tab');

    navTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const target = tab.dataset.tab;
            switchTab(target);
        });
    });
}

function switchTab(tabName) {
    // Update navigation
    document.querySelectorAll('.nav-tab').forEach(tab => {
        tab.classList.toggle('active', tab.dataset.tab === tabName);
    });

    // Update content
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.toggle('active', content.id === `${tabName}-tab`);
    });

    state.currentTab = tabName;

    // Load tab-specific data
    loadTabData(tabName);
}

function loadTabData(tabName) {
    switch(tabName) {
        case 'dashboard':
            loadDashboardData();
            break;
        case 'history':
            loadAnalysisHistory();
            break;
        case 'threats':
            loadActiveThreats();
            break;
        case 'batch':
            loadBatchJobs();
            break;
        case 'reports':
            loadReports();
            break;
    }
}

// ============================================================================
// FILE UPLOAD
// ============================================================================

function initializeUpload() {
    const uploadZone = document.getElementById('upload-zone');
    const fileInput = document.getElementById('file-input');

    if (!uploadZone || !fileInput) return;

    // Click to upload
    uploadZone.addEventListener('click', () => fileInput.click());

    // File selected
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFileUpload(e.target.files[0]);
        }
    });

    // Drag & drop
    uploadZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadZone.classList.add('dragover');
    });

    uploadZone.addEventListener('dragleave', () => {
        uploadZone.classList.remove('dragover');
    });

    uploadZone.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadZone.classList.remove('dragover');

        if (e.dataTransfer.files.length > 0) {
            handleFileUpload(e.dataTransfer.files[0]);
        }
    });
}

async function handleFileUpload(file) {
    // Validate file type
    const validTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/bmp', 'image/tiff'];
    if (!validTypes.includes(file.type)) {
        showNotification('Invalid file type. Please upload an image file.', 'danger');
        return;
    }

    // Validate file size (max 50MB)
    if (file.size > 50 * 1024 * 1024) {
        showNotification('File too large. Maximum size is 50MB.', 'danger');
        return;
    }

    // Create form data
    const formData = new FormData();
    formData.append('file', file);

    // Show progress
    showProgressBar();
    updateProgressBar(0, 'Uploading image...');

    try {
        // Upload file
        const response = await fetch('/api/analysis/upload', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            throw new Error('Upload failed');
        }

        const data = await response.json();

        // Start analysis
        startAnalysis(data.file_path);

    } catch (error) {
        hideProgressBar();
        showNotification(`Upload failed: ${error.message}`, 'danger');
    }
}

async function startAnalysis(filePath) {
    updateProgressBar(10, 'Starting analysis...');

    try {
        const response = await fetch('/api/analysis/start', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                file_path: filePath,
                options: {
                    enable_decryption: true
                }
            })
        });

        if (!response.ok) {
            throw new Error('Analysis start failed');
        }

        const data = await response.json();
        state.activeAnalysis = data.analysis_id;

        // WebSocket will handle progress updates

    } catch (error) {
        hideProgressBar();
        showNotification(`Analysis failed: ${error.message}`, 'danger');
    }
}

// ============================================================================
// PROGRESS BAR
// ============================================================================

function showProgressBar() {
    const container = document.getElementById('progress-container');
    if (container) {
        container.classList.add('active');
    }
}

function hideProgressBar() {
    const container = document.getElementById('progress-container');
    if (container) {
        container.classList.remove('active');
    }
}

function updateProgressBar(percent, message) {
    const bar = document.getElementById('progress-bar');
    const text = document.getElementById('progress-text');
    const percentText = document.getElementById('progress-percent');

    if (bar) {
        bar.style.width = `${percent}%`;
    }

    if (text) {
        text.textContent = message;
    }

    if (percentText) {
        percentText.textContent = `${Math.round(percent)}%`;
    }
}

// ============================================================================
// RESULTS DISPLAY
// ============================================================================

function displayResults(data) {
    const resultsContainer = document.getElementById('results-container');
    if (!resultsContainer) return;

    resultsContainer.innerHTML = '';
    resultsContainer.classList.remove('hidden');

    // Create results grid
    const grid = document.createElement('div');
    grid.className = 'results-grid';

    // Detection summary
    grid.appendChild(createMetricCard(
        data.detection?.anomaly_count || 0,
        'Anomalies Detected',
        'threat-critical'
    ));

    grid.appendChild(createMetricCard(
        data.detection?.confidence ? `${(data.detection.confidence * 100).toFixed(1)}%` : 'N/A',
        'Confidence',
        'threat-high'
    ));

    grid.appendChild(createThreatLevelCard(data.threat_analysis?.threat_assessment?.level || 'UNKNOWN'));

    resultsContainer.appendChild(grid);

    // Detailed results
    if (data.threat_analysis?.apt_attribution?.likely_actor) {
        resultsContainer.appendChild(createAPTCard(data.threat_analysis.apt_attribution));
    }

    if (data.threat_analysis?.modern_techniques?.detected?.length > 0) {
        resultsContainer.appendChild(createTechniquesCard(data.threat_analysis.modern_techniques.detected));
    }

    if (data.decryption) {
        resultsContainer.appendChild(createDecryptionCard(data.decryption));
    }

    if (data.recommendations?.length > 0) {
        resultsContainer.appendChild(createRecommendationsCard(data.recommendations));
    }
}

function createMetricCard(value, label, className = '') {
    const card = document.createElement('div');
    card.className = `metric-card ${className}`;
    card.innerHTML = `
        <div class="metric-value">${value}</div>
        <div class="metric-label">${label}</div>
    `;
    return card;
}

function createThreatLevelCard(level) {
    const card = document.createElement('div');
    card.className = 'metric-card';
    card.innerHTML = `
        <div class="threat-badge threat-${level.toLowerCase()}">${level}</div>
        <div class="metric-label">Threat Level</div>
    `;
    return card;
}

function createAPTCard(aptData) {
    const card = document.createElement('div');
    card.className = 'card';
    card.innerHTML = `
        <div class="card-header">
            <h3 class="card-title">APT Attribution</h3>
            <span class="card-badge">${(aptData.confidence * 100).toFixed(0)}% Confidence</span>
        </div>
        <div class="card-body">
            <div class="alert alert-danger">
                <strong>${aptData.likely_actor}</strong>
                <p>${aptData.description || 'Advanced Persistent Threat detected'}</p>
            </div>
        </div>
    `;
    return card;
}

function createTechniquesCard(techniques) {
    const card = document.createElement('div');
    card.className = 'card';

    const techniquesList = techniques.map(tech => `
        <div class="timeline-item">
            <div class="timeline-marker"></div>
            <div class="timeline-content">
                <div class="timeline-title">${tech.name}</div>
                <div class="timeline-description">${tech.description}</div>
                <span class="threat-badge threat-${tech.severity.toLowerCase()}">${tech.severity}</span>
            </div>
        </div>
    `).join('');

    card.innerHTML = `
        <div class="card-header">
            <h3 class="card-title">2026 Techniques Detected</h3>
            <span class="card-badge">${techniques.length}</span>
        </div>
        <div class="card-body">
            <div class="timeline">
                ${techniquesList}
            </div>
        </div>
    `;
    return card;
}

function createDecryptionCard(decryption) {
    const card = document.createElement('div');
    card.className = 'card';

    let status, statusClass;
    if (decryption.success) {
        status = 'Full Decryption Successful';
        statusClass = 'alert-success';
    } else if (decryption.partial_success) {
        status = `Partial Decryption (${(decryption.success_rate * 100).toFixed(0)}%)`;
        statusClass = 'alert-warning';
    } else {
        status = 'Decryption Failed';
        statusClass = 'alert-danger';
    }

    card.innerHTML = `
        <div class="card-header">
            <h3 class="card-title">Decryption Results</h3>
            <span class="card-badge">${decryption.time_elapsed?.toFixed(1) || 0}s</span>
        </div>
        <div class="card-body">
            <div class="alert ${statusClass}">
                <strong>${status}</strong>
            </div>
            ${decryption.extracted_data ? `
                <div class="mt-2">
                    <strong>Extracted Data:</strong>
                    <pre class="mt-1" style="background: var(--bg-tertiary); padding: 1rem; border-radius: 4px; overflow-x: auto;">${escapeHtml(decryption.extracted_data)}</pre>
                </div>
            ` : ''}
            ${decryption.probes_used ? `
                <div class="mt-2">
                    <strong>Probes Used:</strong> ${decryption.probes_used.join(', ')}
                </div>
            ` : ''}
        </div>
    `;
    return card;
}

function createRecommendationsCard(recommendations) {
    const card = document.createElement('div');
    card.className = 'card';

    const recsList = recommendations.map(rec => `
        <div class="alert alert-info">
            <span class="threat-badge threat-${rec.priority.toLowerCase()}">${rec.priority}</span>
            <div class="mt-1">
                <strong>${rec.action}</strong>
                <p>${rec.details}</p>
            </div>
        </div>
    `).join('');

    card.innerHTML = `
        <div class="card-header">
            <h3 class="card-title">Recommendations</h3>
            <span class="card-badge">${recommendations.length}</span>
        </div>
        <div class="card-body">
            ${recsList}
        </div>
    `;
    return card;
}

// ============================================================================
// DASHBOARD DATA
// ============================================================================

async function loadDashboardData() {
    try {
        const response = await fetch('/api/dashboard/stats');
        const data = await response.json();

        updateDashboardStats(data);
    } catch (error) {
        console.error('Failed to load dashboard data:', error);
    }
}

function updateDashboardStats(data) {
    // Update stat boxes
    updateElement('total-analyses', data.total_analyses || 0);
    updateElement('threats-detected', data.threats_detected || 0);
    updateElement('avg-confidence', data.avg_confidence ? `${(data.avg_confidence * 100).toFixed(1)}%` : 'N/A');
    updateElement('detection-rate', data.detection_rate ? `${(data.detection_rate * 100).toFixed(1)}%` : 'N/A');

    // Update threat distribution chart
    if (data.threat_distribution) {
        renderThreatDistribution(data.threat_distribution);
    }
}

// ============================================================================
// HISTORY
// ============================================================================

async function loadAnalysisHistory() {
    try {
        const response = await fetch('/api/jobs/history?limit=50');
        const data = await response.json();

        state.analysisHistory = data.jobs || [];
        renderHistoryTable(state.analysisHistory);
    } catch (error) {
        console.error('Failed to load history:', error);
    }
}

function renderHistoryTable(history) {
    const tbody = document.getElementById('history-tbody');
    if (!tbody) return;

    tbody.innerHTML = '';

    if (history.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="text-center">No analysis history</td></tr>';
        return;
    }

    history.forEach(job => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${formatTimestamp(job.timestamp)}</td>
            <td>${truncate(job.file_info?.filename || 'Unknown', 30)}</td>
            <td><span class="threat-badge threat-${job.threat_level?.toLowerCase() || 'minimal'}">${job.threat_level || 'UNKNOWN'}</span></td>
            <td>${job.detection?.anomaly_count || 0}</td>
            <td>${job.detection?.confidence ? `${(job.detection.confidence * 100).toFixed(1)}%` : 'N/A'}</td>
            <td>
                <button class="btn btn-secondary btn-sm" onclick="viewAnalysis('${job.analysis_id}')">View</button>
                <button class="btn btn-secondary btn-sm" onclick="downloadReport('${job.analysis_id}')">Report</button>
            </td>
        `;
        tbody.appendChild(row);
    });
}

function addToHistory(analysis) {
    state.analysisHistory.unshift(analysis);
    if (state.analysisHistory.length > 100) {
        state.analysisHistory.pop();
    }
    renderHistoryTable(state.analysisHistory);
}

// ============================================================================
// ACTIVE THREATS
// ============================================================================

async function loadActiveThreats() {
    try {
        const response = await fetch('/api/dashboard/active-threats');
        const data = await response.json();

        renderActiveThreats(data.threats || []);
    } catch (error) {
        console.error('Failed to load active threats:', error);
    }
}

function renderActiveThreats(threats) {
    const container = document.getElementById('threats-container');
    if (!container) return;

    container.innerHTML = '';

    if (threats.length === 0) {
        container.innerHTML = '<div class="alert alert-success">No active threats detected</div>';
        return;
    }

    threats.forEach(threat => {
        const card = createAPTCard(threat);
        container.appendChild(card);
    });
}

// ============================================================================
// BATCH PROCESSING
// ============================================================================

async function loadBatchJobs() {
    try {
        const response = await fetch('/api/jobs/batch');
        const data = await response.json();

        renderBatchJobs(data.jobs || []);
    } catch (error) {
        console.error('Failed to load batch jobs:', error);
    }
}

function renderBatchJobs(jobs) {
    const container = document.getElementById('batch-container');
    if (!container) return;

    container.innerHTML = '';

    if (jobs.length === 0) {
        container.innerHTML = '<div class="alert alert-info">No batch jobs running</div>';
        return;
    }

    jobs.forEach(job => {
        const card = document.createElement('div');
        card.className = 'card';
        card.innerHTML = `
            <div class="card-header">
                <h3 class="card-title">${job.name}</h3>
                <span class="card-badge">${job.status}</span>
            </div>
            <div class="card-body">
                <div class="progress-bar-wrapper">
                    <div class="progress-bar" style="width: ${job.progress}%"></div>
                </div>
                <div class="progress-text">
                    <span>${job.completed} / ${job.total} completed</span>
                    <span>${job.progress.toFixed(1)}%</span>
                </div>
            </div>
        `;
        container.appendChild(card);
    });
}

// ============================================================================
// REPORTS
// ============================================================================

async function loadReports() {
    try {
        const response = await fetch('/api/reports/list');
        const data = await response.json();

        renderReports(data.reports || []);
    } catch (error) {
        console.error('Failed to load reports:', error);
    }
}

function renderReports(reports) {
    const container = document.getElementById('reports-container');
    if (!container) return;

    container.innerHTML = '';

    if (reports.length === 0) {
        container.innerHTML = '<div class="alert alert-info">No reports generated</div>';
        return;
    }

    reports.forEach(report => {
        const card = document.createElement('div');
        card.className = 'card';
        card.innerHTML = `
            <div class="card-header">
                <h3 class="card-title">${report.filename}</h3>
                <span class="card-badge">${report.format.toUpperCase()}</span>
            </div>
            <div class="card-body">
                <div class="stat-box-label">${formatTimestamp(report.timestamp)}</div>
                <div class="mt-2">
                    <button class="btn btn-primary" onclick="downloadReport('${report.id}', '${report.format}')">Download</button>
                </div>
            </div>
        `;
        container.appendChild(card);
    });
}

async function downloadReport(analysisId, format = 'pdf') {
    try {
        const response = await fetch(`/api/reports/download/${analysisId}?format=${format}`);
        const blob = await response.blob();

        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `stegoguard_report_${analysisId}.${format}`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);

        showNotification('Report downloaded', 'success');
    } catch (error) {
        showNotification('Failed to download report', 'danger');
    }
}

// ============================================================================
// SYSTEM METRICS
// ============================================================================

async function loadSystemMetrics() {
    try {
        const response = await fetch('/api/system/metrics');
        const data = await response.json();

        updateSystemMetrics(data);
    } catch (error) {
        console.error('Failed to load system metrics:', error);
    }
}

function updateSystemMetrics(metrics) {
    updateElement('cpu-usage', metrics.cpu_usage ? `${metrics.cpu_usage.toFixed(1)}%` : 'N/A');
    updateElement('memory-usage', metrics.memory_usage ? `${metrics.memory_usage.toFixed(1)}%` : 'N/A');
    updateElement('active-analyses', metrics.active_analyses || 0);
}

function startMetricsPolling() {
    setInterval(loadSystemMetrics, 5000); // Poll every 5 seconds
}

function updateConnectionStatus(connected) {
    const indicator = document.getElementById('connection-status');
    if (indicator) {
        indicator.className = connected ? 'status-connected' : 'status-disconnected';
        indicator.textContent = connected ? 'Connected' : 'Disconnected';
    }
}

// ============================================================================
// NOTIFICATIONS
// ============================================================================

function showNotification(message, type = 'info') {
    const container = document.getElementById('notifications-container') || createNotificationsContainer();

    const notification = document.createElement('div');
    notification.className = `alert alert-${type}`;
    notification.textContent = message;

    container.appendChild(notification);

    setTimeout(() => {
        notification.style.opacity = '0';
        setTimeout(() => notification.remove(), 300);
    }, 5000);
}

function createNotificationsContainer() {
    const container = document.createElement('div');
    container.id = 'notifications-container';
    container.style.cssText = 'position: fixed; top: 20px; right: 20px; z-index: 10000; width: 400px;';
    document.body.appendChild(container);
    return container;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function updateElement(id, value) {
    const element = document.getElementById(id);
    if (element) {
        element.textContent = value;
    }
}

function formatTimestamp(timestamp) {
    if (!timestamp) return 'N/A';
    const date = new Date(timestamp);
    return date.toLocaleString();
}

function truncate(str, length) {
    if (!str) return '';
    return str.length > length ? str.substring(0, length) + '...' : str;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function viewAnalysis(analysisId) {
    // Load and display specific analysis
    fetch(`/api/analysis/${analysisId}`)
        .then(response => response.json())
        .then(data => {
            displayResults(data);
            switchTab('scan');
        })
        .catch(error => {
            showNotification('Failed to load analysis', 'danger');
        });
}

// ============================================================================
// E2EE FUNCTIONS
// ============================================================================

function toggleE2EEOptions(value) {
    const keyInput = document.getElementById('e2ee-key-input');
    const generateKeypair = document.getElementById('e2ee-generate-keypair');

    if (value === 'none') {
        keyInput.style.display = 'none';
        generateKeypair.style.display = 'none';
    } else {
        keyInput.style.display = 'flex';
        generateKeypair.style.display = 'flex';
    }
}

async function generateE2EEKeypair() {
    const curve = document.getElementById('e2ee-select').value;

    if (curve === 'none') {
        showNotification('Please select an E2EE curve first', 'warning');
        return;
    }

    try {
        showNotification('Generating keypair...', 'info');

        const response = await fetch('/api/system/e2ee/generate-keypair', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ curve })
        });

        const data = await response.json();

        if (data.success) {
            document.getElementById('public-key-display').textContent = data.public_key;
            document.getElementById('private-key-display').textContent = data.private_key;
            document.getElementById('generated-keypair').style.display = 'block';
            document.getElementById('private-key-input').value = data.private_key;

            showNotification('Keypair generated successfully', 'success');
        } else {
            showNotification('Failed to generate keypair: ' + data.error, 'danger');
        }
    } catch (error) {
        console.error('Error generating keypair:', error);
        showNotification('Error generating keypair', 'danger');
    }
}

function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    const text = element.textContent;

    navigator.clipboard.writeText(text).then(() => {
        showNotification('Copied to clipboard!', 'success');
    }).catch(err => {
        console.error('Failed to copy:', err);
        showNotification('Failed to copy', 'danger');
    });
}

// ============================================================================
// EXPORT
// ============================================================================

window.StegoGuardDashboard = {
    switchTheme,
    switchTab,
    handleFileUpload,
    viewAnalysis,
    downloadReport,
    showNotification
};

// Export E2EE functions globally
window.toggleE2EEOptions = toggleE2EEOptions;
window.generateE2EEKeypair = generateE2EEKeypair;
window.copyToClipboard = copyToClipboard;
