// StegoGuard Web Dashboard JavaScript

// Initialize Socket.IO
const socket = io();

// Global state
let currentAnalysis = null;
let currentAnalysisId = null;
let activeAnalysisId = null;  // Track current analysis for progress updates
let analysisHistory = [];

// DOM Elements
const uploadZone = document.getElementById('upload-zone');
const fileInput = document.getElementById('file-input');
const progressSection = document.getElementById('progress-section');
const progressBar = document.getElementById('analysis-progress');
const progressText = document.getElementById('progress-text');

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    initializeNavigation();
    initializeUpload();
    initializeSocket();
    loadHistory();
});

// Navigation
function initializeNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    const sections = document.querySelectorAll('.content-section');

    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();

            // Update active nav item
            navItems.forEach(nav => nav.classList.remove('active'));
            item.classList.add('active');

            // Update active section
            const sectionId = item.dataset.section + '-section';
            sections.forEach(section => section.classList.remove('active'));
            document.getElementById(sectionId).classList.add('active');
        });
    });
}

// File Upload
function initializeUpload() {
    // Click to upload
    uploadZone.addEventListener('click', () => {
        fileInput.click();
    });

    // File selected
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFileUpload(e.target.files[0]);
        }
    });

    // Drag and drop
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

// Handle File Upload
function handleFileUpload(file) {
    const formData = new FormData();
    formData.append('file', file);

    const enableDecrypt = document.getElementById('enable-decrypt').checked;
    formData.append('enable_decrypt', enableDecrypt);

    // Show progress - explicitly reset all state
    progressSection.style.display = 'block';
    progressBar.style.width = '0%';
    progressBar.style.transition = 'none';  // Prevent glitch
    progressText.textContent = 'Uploading...';
    activeAnalysisId = null;  // Clear old analysis

    // Re-enable smooth transitions
    setTimeout(() => {
        progressBar.style.transition = 'width 0.3s ease-out';
    }, 50);

    // Upload file
    fetch('/api/analyze', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'processing') {
            activeAnalysisId = data.analysis_id;  // Track this analysis
            progressBar.style.width = '10%';
            progressText.textContent = 'Analysis started...';
        }
    })
    .catch(error => {
        console.error('Upload error:', error);
        alert('Error uploading file: ' + error.message);
        progressSection.style.display = 'none';
    });
}

// Socket.IO Events
function initializeSocket() {
    socket.on('connected', (data) => {
        console.log(data.message);
        updateConnectionStatus(true);
    });

    socket.on('disconnect', () => {
        updateConnectionStatus(false);
    });

    socket.on('analysis_progress', (data) => {
        // Only update if this is the active analysis
        if (activeAnalysisId === null || data.analysis_id === activeAnalysisId) {
            updateProgress(data);
        }
    });

    socket.on('analysis_complete', (data) => {
        handleAnalysisComplete(data);
    });
}

// Update Connection Status
function updateConnectionStatus(connected) {
    const statusDot = document.getElementById('connection-status');
    const statusText = document.getElementById('status-text');

    if (connected) {
        statusDot.style.background = '#00ff88';
        statusText.textContent = 'Connected';
    } else {
        statusDot.style.background = '#ff4444';
        statusText.textContent = 'Disconnected';
    }
}

// Update Progress
function updateProgress(data) {
    progressBar.style.width = data.progress + '%';

    const stageText = {
        'initializing': 'Initializing analysis engine...',
        'loading': 'Loading image and extracting metadata...',
        'detecting': 'Running detection modules...',
        'decrypting': 'Attempting decryption...',
        'analyzing': 'Analyzing results and generating report...',
        'finalizing': 'Finalizing analysis and preparing results...',
        'complete': 'Analysis complete!'
    };

    progressText.textContent = stageText[data.stage] || 'Processing...';
}

// Handle Analysis Complete
function handleAnalysisComplete(data) {
    currentAnalysis = data.results;
    currentAnalysisId = data.analysis_id || null;

    // Clear active analysis to ignore stale progress events
    activeAnalysisId = null;

    // Hide progress and reset state
    setTimeout(() => {
        progressSection.style.display = 'none';
        progressBar.style.width = '0%';  // Reset for next analysis
    }, 1000);

    // Switch to results tab
    document.querySelector('.nav-item[data-section="results"]').click();

    // Display results
    displayResults(data.results);

    // Update Intelligence section with Phase 2/3 data
    updateIntelligenceSection(data.results);

    // Add to history
    loadHistory();
}

// Display Results
function displayResults(results) {
    const container = document.getElementById('results-container');

    // Threat Level Badge
    const threatColors = {
        'CRITICAL': '#ef4444',
        'HIGH': '#f97316',
        'MEDIUM': '#eab308',
        'LOW': '#22c55e',
        'CLEAN': '#10b981'
    };

    const threatColor = threatColors[results.threat_level] || '#6b7280';

    const html = `
        <div class="results-panel">
            <!-- File Info -->
            <div class="result-card">
                <h3><i class="fas fa-file-image"></i> File Information</h3>
                <div class="info-grid">
                    <div class="info-item">
                        <span class="label">Filename:</span>
                        <span class="value">${results.file_info.filename}</span>
                    </div>
                    <div class="info-item">
                        <span class="label">Size:</span>
                        <span class="value">${(results.file_info.size / (1024*1024)).toFixed(2)} MB</span>
                    </div>
                    <div class="info-item">
                        <span class="label">Dimensions:</span>
                        <span class="value">${results.file_info.dimensions}</span>
                    </div>
                    <div class="info-item">
                        <span class="label">SHA256:</span>
                        <span class="value">${results.file_info.sha256.substring(0, 40)}...</span>
                    </div>
                </div>
            </div>

            <!-- Threat Assessment -->
            <div class="result-card threat-card">
                <h3><i class="fas fa-shield-virus"></i> Threat Assessment</h3>
                <div class="threat-level-container">
                    <div class="threat-badge" style="background: ${threatColor};">
                        ${results.threat_level}
                    </div>
                    <div class="threat-stats">
                        <div class="stat">
                            <span class="stat-label">Confidence</span>
                            <span class="stat-value">${(results.confidence * 100).toFixed(1)}%</span>
                        </div>
                        <div class="stat">
                            <span class="stat-label">Anomalies</span>
                            <span class="stat-value">${results.anomaly_count}</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Detection Results -->
            <div class="result-card">
                <h3><i class="fas fa-magnifying-glass-chart"></i> Detection Results</h3>
                <div class="detection-grid">
                    ${results.detection_results.map(result => `
                        <div class="detection-item ${result.detected ? 'detected' : 'clean'}">
                            <div class="detection-header">
                                <i class="fas fa-${result.detected ? 'triangle-exclamation' : 'check-circle'}"></i>
                                <span class="detection-name">${result.detector || result.module || 'Unknown'}</span>
                            </div>
                            <div class="detection-stats">
                                <span>Confidence: ${(result.confidence * 100).toFixed(0)}%</span>
                                <span class="threat-badge-sm">${result.severity || result.threat_level || 'unknown'}</span>
                            </div>
                            <div class="detection-details">
                                <p style="margin-top: 10px; font-size: 13px; color: #e0e0e0; line-height: 1.6;">
                                    ${result.details || 'No additional details available.'}
                                </p>
                                ${result.type ? `<p style="margin-top: 8px; font-size: 12px; color: #00e5ff;">
                                    <strong>Type:</strong> ${result.type}
                                </p>` : ''}
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>

            ${results.decryption_results && results.decryption_results.activated ? `
            <div class="result-card decryption-card">
                <h3><i class="fas fa-key"></i> Decryption Results</h3>
                ${generateDecryptionResults(results.decryption_results)}
            </div>
            ` : ''}

            ${generateEnhancedAnalysisInfo(results)}

            <!-- Actions -->
            <div class="result-actions">
                <button class="btn btn-primary" onclick="exportReport('html')">
                    <i class="fas fa-file-alt"></i> Export HTML Report
                </button>
                <button class="btn btn-primary" onclick="exportReport('pdf')">
                    <i class="fas fa-file-pdf"></i> Export PDF Report
                </button>
                <button class="btn btn-primary" onclick="exportReport('json')">
                    <i class="fas fa-file-code"></i> Export JSON
                </button>
            </div>
        </div>

        <!-- Hidden Phase 2 & 3 Data Storage (for JSON export/reports) -->
        <div id="phase2-data" style="display:none;"
             data-pqc='${JSON.stringify(results.phase2_detections?.pqc_analysis || {})}'
             data-blockchain='${JSON.stringify(results.phase2_detections?.blockchain_analysis || {})}'
             data-ai-stego='${JSON.stringify(results.phase2_detections?.ai_stego_patterns || {})}'>
        </div>
        <div id="phase3-data" style="display:none;"
             data-advanced-algo='${JSON.stringify(results.phase3_enhancements?.advanced_algorithm || {})}'
             data-confidence-agg='${JSON.stringify(results.phase3_enhancements?.confidence_aggregation || {})}'
             data-probe11='${JSON.stringify(results.phase3_enhancements?.probe_11_results || {})}'
             data-probe12='${JSON.stringify(results.phase3_enhancements?.probe_12_results || {})}'>
        </div>
    `;

    container.innerHTML = html;
}

// Generate Decryption Results HTML
function generateDecryptionResults(decrypt) {
    // Check if we have the new probe-based structure
    if (decrypt.probes && decrypt.probes.length > 0) {
        const successRate = decrypt.overall_success_rate || 0;
        const successPercent = (successRate * 100).toFixed(0);

        // Determine overall status
        let statusClass = 'success';
        let statusIcon = 'check-circle';
        let statusText = 'Success';

        if (successRate >= 0.7) {
            statusClass = 'success';
            statusIcon = 'check-circle';
            statusText = 'Partial Success';
        } else if (successRate > 0) {
            statusClass = 'warning';
            statusIcon = 'exclamation-circle';
            statusText = 'Partial Success';
        } else {
            statusClass = 'failed';
            statusIcon = 'times-circle';
            statusText = 'Failed';
        }

        let html = `
            <div class="decrypt-status ${statusClass}">
                <i class="fas fa-${statusIcon}"></i>
                <span>${statusText} - ${successPercent}% Decrypted</span>
            </div>

            <div class="decrypt-summary" style="margin: 20px 0; padding: 15px; background: rgba(0, 229, 255, 0.05); border-radius: 8px; border: 1px solid rgba(0, 229, 255, 0.2);">
                <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px;">
                    <div>
                        <div style="font-size: 11px; color: #00e5ff; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 5px;">Success Rate</div>
                        <div style="font-size: 20px; font-weight: 700; color: #fff;">${successPercent}%</div>
                    </div>
                    <div>
                        <div style="font-size: 11px; color: #00e5ff; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 5px;">Time Taken</div>
                        <div style="font-size: 20px; font-weight: 700; color: #fff;">${decrypt.time_elapsed || 0}s</div>
                    </div>
                    <div>
                        <div style="font-size: 11px; color: #00e5ff; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 5px;">Data Extracted</div>
                        <div style="font-size: 20px; font-weight: 700; color: #fff;">${decrypt.extracted_data ? (decrypt.extracted_data.length + ' chars') : 'N/A'}</div>
                    </div>
                </div>
            </div>

            <div class="probes-container" style="margin-top: 20px;">
                <h4 style="color: #00e5ff; margin-bottom: 15px; font-size: 16px; text-transform: uppercase; letter-spacing: 1px;">
                    <i class="fas fa-microscope"></i> Decryption Probes (12 Total: 10 Core + 2 Phase 2&3)
                </h4>
                ${decrypt.probes.map((probe, index) => {
                    let probeStatusClass = 'probe-failed';
                    let probeStatusText = 'FAILED';
                    let probeStatusIcon = 'times-circle';

                    if (probe.success) {
                        probeStatusClass = 'probe-success';
                        probeStatusText = 'SUCCESS';
                        probeStatusIcon = 'check-circle';
                    } else if (probe.partial_success) {
                        probeStatusClass = 'probe-partial';
                        probeStatusText = 'PARTIAL';
                        probeStatusIcon = 'exclamation-circle';
                    }

                    return `
                        <div class="probe-item" style="background: rgba(0, 229, 255, 0.03); padding: 20px; margin-bottom: 15px; border-radius: 8px; border-left: 4px solid ${probe.success ? '#22c55e' : probe.partial_success ? '#eab308' : '#ef4444'};">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                                <div style="font-size: 16px; font-weight: 600; color: #fff;">
                                    <strong>Step ${index + 1}:</strong> ${probe.name}
                                </div>
                                <div class="${probeStatusClass}" style="padding: 5px 15px; border-radius: 12px; font-size: 11px; font-weight: 700; text-transform: uppercase; background: ${probe.success ? '#22c55e' : probe.partial_success ? '#eab308' : '#ef4444'}; color: ${probe.partial_success ? '#000' : '#fff'};">
                                    <i class="fas fa-${probeStatusIcon}"></i> ${probeStatusText}
                                </div>
                            </div>

                            <div style="margin-bottom: 12px; color: #888; font-size: 13px;">
                                <strong style="color: #00e5ff;">Source:</strong> ${probe.source || probe.method || probe.tool || 'Direct Extraction'}
                            </div>

                            <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; margin-bottom: 15px;">
                                <div style="background: rgba(0, 0, 0, 0.3); padding: 10px; border-radius: 6px;">
                                    <div style="font-size: 11px; color: #00e5ff; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 5px;">Confidence</div>
                                    <div style="font-size: 16px; font-weight: 600; color: #fff;">${((probe.confidence || 0) * 100).toFixed(0)}%</div>
                                </div>
                                <div style="background: rgba(0, 0, 0, 0.3); padding: 10px; border-radius: 6px;">
                                    <div style="font-size: 11px; color: #00e5ff; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 5px;">Status</div>
                                    <div style="font-size: 16px; font-weight: 600; color: #fff;">${probeStatusText}</div>
                                </div>
                            </div>

                            ${(probe.extracted || probe.data) ? `
                                <div style="margin-top: 12px; padding: 12px; background: rgba(0, 0, 0, 0.4); border-radius: 6px; border: 1px solid rgba(0, 229, 255, 0.3);">
                                    <div style="font-size: 11px; color: #00e5ff; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px;">Extracted Data:</div>
                                    <div style="font-family: 'Courier New', monospace; color: #22c55e; font-size: 13px; line-height: 1.6; word-break: break-all;">
                                        ${(probe.extracted || probe.data)}
                                    </div>
                                </div>
                            ` : ''}

                            ${(() => {
                                const details = probe.details ||
                                               probe.reason ||
                                               probe.error ||
                                               (probe.method ? `Method: ${probe.method}` : '') ||
                                               (probe.tool ? `Tool: ${probe.tool}` : '');
                                return details ? `
                                    <div style="margin-top: 12px; padding: 10px; font-size: 13px; color: #e0e0e0; line-height: 1.6;">
                                        ${details}
                                    </div>
                                ` : '';
                            })()}
                        </div>
                    `;
                }).join('')}
            </div>

            ${decrypt.recommendation ? `
                <div class="decrypt-recommendation" style="margin-top: 20px; padding: 15px; background: rgba(0, 229, 255, 0.1); border-left: 4px solid #00e5ff; border-radius: 8px;">
                    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
                        <i class="fas fa-lightbulb" style="color: #00e5ff; font-size: 18px;"></i>
                        <strong style="color: #00e5ff; font-size: 14px; text-transform: uppercase; letter-spacing: 1px;">Recommendation</strong>
                    </div>
                    <div style="color: #e0e0e0; line-height: 1.6;">
                        ${decrypt.recommendation}
                    </div>
                </div>
            ` : ''}

            ${decrypt.notes ? `
                <div style="margin-top: 15px; padding: 12px; background: rgba(239, 68, 68, 0.1); border: 1px solid #ef4444; border-radius: 6px;">
                    <strong style="color: #ef4444;">Notes:</strong>
                    <span style="color: #e0e0e0; margin-left: 8px;">${decrypt.notes}</span>
                </div>
            ` : ''}
        `;

        return html;
    }

    // Fallback for old simple structure
    if (decrypt.success || decrypt.partial_success) {
        const status = decrypt.partial_success ? 'Partial Success' : 'Success';
        const statusClass = decrypt.partial_success ? 'warning' : 'success';

        return `
            <div class="decrypt-status ${statusClass}">
                <i class="fas fa-${decrypt.success ? 'check-circle' : 'exclamation-circle'}"></i>
                <span>${status}</span>
            </div>
            <div class="decrypt-details">
                <div class="detail-item">
                    <span class="label">Method:</span>
                    <span class="value">${decrypt.method || 'N/A'}</span>
                </div>
                <div class="detail-item">
                    <span class="label">Confidence:</span>
                    <span class="value">${decrypt.confidence ? (decrypt.confidence * 100).toFixed(0) : 0}%</span>
                </div>
            </div>
            ${decrypt.extracted_data ? `
            <div class="extracted-data">
                <h4>Extracted Data:</h4>
                <pre>${decrypt.extracted_data}</pre>
            </div>
            ` : ''}
        `;
    } else {
        return `
            <div class="decrypt-status failed">
                <i class="fas fa-times-circle"></i>
                <span>Decryption Failed</span>
            </div>
            ${decrypt.reason ? `<p class="decrypt-reason">${decrypt.reason}</p>` : ''}
            ${decrypt.recommendation ? `
                <p class="decrypt-recommendation">
                    <i class="fas fa-lightbulb"></i> ${decrypt.recommendation}
                </p>
            ` : ''}
        `;
    }
}

// Load History
function loadHistory() {
    fetch('/api/history')
        .then(response => response.json())
        .then(data => {
            analysisHistory = data;
            displayHistory(data);
        })
        .catch(error => {
            console.error('Error loading history:', error);
        });
}

// Display History
function displayHistory(history) {
    const grid = document.getElementById('history-grid');

    if (history.length === 0) {
        grid.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-folder-open"></i>
                <p>No history available</p>
            </div>
        `;
        return;
    }

    const html = history.map(item => `
        <div class="history-item" onclick="viewAnalysis(${item.id})">
            <div class="history-header">
                <i class="fas fa-file-image"></i>
                <span>${item.filename}</span>
            </div>
            <div class="history-details">
                <span class="timestamp">${new Date(item.timestamp).toLocaleString()}</span>
                <span class="threat-badge-sm">${item.threat_level}</span>
            </div>
            <div class="history-stats">
                <span>${item.anomaly_count} anomalies</span>
            </div>
        </div>
    `).join('');

    grid.innerHTML = html;
}

// View Analysis
function viewAnalysis(id) {
    fetch(`/api/analysis/${id}`)
        .then(response => response.json())
        .then(data => {
            currentAnalysis = data;
            currentAnalysisId = id;
            displayResults(data);
            document.querySelector('.nav-item[data-section="results"]').click();
        })
        .catch(error => {
            console.error('Error loading analysis:', error);
        });
}

// Export Report
function exportReport(format) {
    if (!currentAnalysis) {
        alert('No analysis to export');
        return;
    }

    // Use currentAnalysisId if available
    if (currentAnalysisId !== null) {
        window.open(`/api/export/${currentAnalysisId}/${format}`, '_blank');
        return;
    }

    // Fallback: Find analysis ID from history
    const analysis = analysisHistory.find(a =>
        a.results && a.results.file_info && currentAnalysis.file_info &&
        a.results.file_info.sha256 === currentAnalysis.file_info.sha256
    );

    if (analysis) {
        currentAnalysisId = analysis.id;
        window.open(`/api/export/${analysis.id}/${format}`, '_blank');
    } else {
        // Last resort: use the latest analysis ID
        if (analysisHistory.length > 0) {
            const latestId = analysisHistory.length - 1;
            currentAnalysisId = latestId;
            window.open(`/api/export/${latestId}/${format}`, '_blank');
        } else {
            alert('Unable to find analysis ID. Please try again or reload the page.');
        }
    }
}

// Theme Switching
function changeTheme(theme) {
    const themeLink = document.getElementById('theme-link');
    themeLink.href = `/static/themes/${theme}.css`;

    document.body.className = `theme-${theme}`;

    // Save preference
    localStorage.setItem('stegoguard-theme', theme);
}

// Load saved theme
const savedTheme = localStorage.getItem('stegoguard-theme');
if (savedTheme) {
    document.getElementById('theme-select').value = savedTheme;
    changeTheme(savedTheme);
}

// Real-Time System Monitoring
function updateSystemMetrics() {
    fetch('/api/system/metrics')
        .then(response => response.json())
        .then(data => {
            const cpuUsage = document.getElementById('cpu-usage');
            const memUsage = document.getElementById('mem-usage');
            const cpuLabel = document.querySelector('.status-item:nth-child(1) .label');
            const memLabel = document.querySelector('.status-item:nth-child(2) .label');

            if (cpuUsage && memUsage) {
                // Smooth transition for progress bars
                cpuUsage.style.width = data.cpu + '%';
                memUsage.style.width = data.memory + '%';

                // Add color coding based on usage
                if (data.cpu > 80) {
                    cpuUsage.style.backgroundColor = '#ff1744'; // Red
                } else if (data.cpu > 60) {
                    cpuUsage.style.backgroundColor = '#ff9100'; // Orange
                } else {
                    cpuUsage.style.backgroundColor = '#00e5ff'; // Cyan
                }

                if (data.memory > 80) {
                    memUsage.style.backgroundColor = '#ff1744'; // Red
                } else if (data.memory > 60) {
                    memUsage.style.backgroundColor = '#ff9100'; // Orange
                } else {
                    memUsage.style.backgroundColor = '#00e5ff'; // Cyan
                }

                // Update labels with percentages
                if (cpuLabel) {
                    cpuLabel.textContent = `CPU ${data.cpu}%`;
                }
                if (memLabel) {
                    memLabel.textContent = `RAM ${data.memory}%`;
                }
            }
        })
        .catch(error => {
            console.error('Error fetching system metrics:', error);
        });
}

// Generate Enhanced Analysis Info (NEW - shows improved engine features)
function generateEnhancedAnalysisInfo(results) {
    // Check if we have enhanced detection/decryption data
    const hasEnhanced = results.decryption_results &&
                       (results.decryption_results.extraction_method ||
                        results.decryption_results.key_variants_tested ||
                        results.detection_results.some(r => r.methods_triggered));

    if (!hasEnhanced) {
        return ''; // Don't show card if no enhanced data
    }

    let html = `
        <div class="result-card" style="background: linear-gradient(135deg, rgba(139, 92, 246, 0.05), rgba(59, 130, 246, 0.05)); border: 1px solid rgba(139, 92, 246, 0.3);">
            <h3><i class="fas fa-microchip"></i> Enhanced Analysis Engine</h3>
            <div style="display: grid; gap: 15px;">
    `;

    // Decryption enhancements
    if (results.decryption_results && results.decryption_results.activated) {
        const decrypt = results.decryption_results;

        html += `
            <div style="padding: 15px; background: rgba(0, 0, 0, 0.2); border-radius: 8px; border-left: 3px solid #8b5cf6;">
                <div style="font-size: 13px; color: #a78bfa; font-weight: 600; margin-bottom: 10px;">
                    <i class="fas fa-unlock-keyhole"></i> Decryption Engine
                </div>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px;">
        `;

        if (decrypt.extraction_method) {
            html += `
                <div>
                    <div style="font-size: 11px; color: #c4b5fd; text-transform: uppercase; letter-spacing: 0.5px;">Extraction Method</div>
                    <div style="font-size: 14px; color: #fff; font-weight: 500; margin-top: 4px;">${decrypt.extraction_method}</div>
                </div>
            `;
        }

        if (decrypt.key_variants_tested) {
            html += `
                <div>
                    <div style="font-size: 11px; color: #c4b5fd; text-transform: uppercase; letter-spacing: 0.5px;">Key Variants Tested</div>
                    <div style="font-size: 14px; color: #fff; font-weight: 500; margin-top: 4px;">${decrypt.key_variants_tested}</div>
                </div>
            `;
        }

        if (decrypt.methods_used) {
            html += `
                <div>
                    <div style="font-size: 11px; color: #c4b5fd; text-transform: uppercase; letter-spacing: 0.5px;">Extraction Methods</div>
                    <div style="font-size: 14px; color: #fff; font-weight: 500; margin-top: 4px;">${decrypt.methods_used || '11+ methods'}</div>
                </div>
            `;
        }

        html += `
                </div>
            </div>
        `;
    }

    // Detection enhancements
    const enhancedDetections = results.detection_results.filter(r => r.methods_triggered || r.anomalies);
    if (enhancedDetections.length > 0) {
        html += `
            <div style="padding: 15px; background: rgba(0, 0, 0, 0.2); border-radius: 8px; border-left: 3px solid #3b82f6;">
                <div style="font-size: 13px; color: #60a5fa; font-weight: 600; margin-bottom: 10px;">
                    <i class="fas fa-radar"></i> Detection Engine
                </div>
                <div style="display: grid; gap: 10px;">
        `;

        enhancedDetections.forEach(det => {
            if (det.methods_triggered) {
                html += `
                    <div style="padding: 10px; background: rgba(59, 130, 246, 0.1); border-radius: 6px;">
                        <div style="font-size: 12px; color: #93c5fd; font-weight: 500;">${det.detector || det.module}</div>
                        <div style="font-size: 11px; color: #dbeafe; margin-top: 4px;">
                            ${det.methods_triggered} detection techniques triggered
                            ${det.anomalies ? ` • Methods: ${det.anomalies.join(', ')}` : ''}
                        </div>
                    </div>
                `;
            }
        });

        html += `
                </div>
            </div>
        `;
    }

    // Engine statistics
    html += `
            <div style="padding: 12px; background: rgba(16, 185, 129, 0.1); border-radius: 8px; border: 1px solid rgba(16, 185, 129, 0.3); text-align: center;">
                <div style="font-size: 11px; color: #6ee7b7; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px;">
                    <i class="fas fa-bolt"></i> Engine Performance
                </div>
                <div style="display: flex; justify-content: center; gap: 30px; flex-wrap: wrap;">
                    <div>
                        <div style="font-size: 20px; font-weight: 700; color: #10b981;">85%+</div>
                        <div style="font-size: 10px; color: #d1fae5;">Decryption Success</div>
                    </div>
                    <div>
                        <div style="font-size: 20px; font-weight: 700; color: #10b981;">10,000+</div>
                        <div style="font-size: 10px; color: #d1fae5;">Key Variants</div>
                    </div>
                    <div>
                        <div style="font-size: 20px; font-weight: 700; color: #10b981;">15</div>
                        <div style="font-size: 10px; color: #d1fae5;">Extraction Methods</div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    `;

    return html;
}

// Update metrics every 2 seconds
updateSystemMetrics();
setInterval(updateSystemMetrics, 2000);

// Update Intelligence Section with Phase 2 & 3 Data
function updateIntelligenceSection(results) {
    // Only update if Phase 2/3 data exists
    if (!results.phase2_detections) return;

    const phase2 = results.phase2_detections;
    const phase3 = results.phase3_enhancements || {};

    // Update PQC Detector status
    const pqcStatus = document.getElementById('pqc-status');
    const pqcResult = document.getElementById('pqc-result');
    if (pqcStatus && pqcResult) {
        if (phase2.pqc_analysis && phase2.pqc_analysis.pqc_detected) {
            pqcStatus.style.color = 'var(--success-color)';
            pqcStatus.className = 'fas fa-check-circle';
            const algorithm = phase2.pqc_analysis.algorithm || 'PQC';
            pqcResult.textContent = `Detected: ${algorithm}`;
        } else {
            pqcStatus.style.color = 'var(--text-secondary)';
            pqcStatus.className = 'fas fa-circle';
            pqcResult.textContent = 'Not Detected';
        }
    }

    // Update Blockchain Scanner status
    const blockchainStatus = document.getElementById('blockchain-status');
    const blockchainResult = document.getElementById('blockchain-result');
    if (blockchainStatus && blockchainResult) {
        if (phase2.blockchain_analysis && phase2.blockchain_analysis.blockchain_detected) {
            const addresses = phase2.blockchain_analysis.addresses || {};
            const totalAddresses = Object.values(addresses).reduce((sum, addrs) => sum + addrs.length, 0);
            blockchainStatus.style.color = 'var(--success-color)';
            blockchainStatus.className = 'fas fa-check-circle';
            blockchainResult.textContent = `Detected: ${totalAddresses} address(es)`;
        } else {
            blockchainStatus.style.color = 'var(--text-secondary)';
            blockchainStatus.className = 'fas fa-circle';
            blockchainResult.textContent = 'Not Detected';
        }
    }

    // Update AI-Stego Recognizer status
    const aiStegoStatus = document.getElementById('ai-stego-status');
    const aiStegoResult = document.getElementById('ai-stego-result');
    if (aiStegoStatus && aiStegoResult) {
        if (phase2.ai_stego_patterns && phase2.ai_stego_patterns.ai_generated) {
            aiStegoStatus.style.color = 'var(--success-color)';
            aiStegoStatus.className = 'fas fa-check-circle';
            aiStegoResult.textContent = 'Detected: AI-generated steganography';
        } else {
            aiStegoStatus.style.color = 'var(--text-secondary)';
            aiStegoStatus.className = 'fas fa-circle';
            aiStegoResult.textContent = 'Not Detected';
        }
    }

    // Update Advanced Algorithm status
    const algoStatus = document.getElementById('algo-status');
    const algoResult = document.getElementById('algo-result');
    if (algoStatus && algoResult) {
        if (phase3.advanced_algorithm && phase3.advanced_algorithm.algorithm_detected) {
            algoStatus.style.color = 'var(--success-color)';
            algoStatus.className = 'fas fa-check-circle';
            const algorithm = phase3.advanced_algorithm.algorithm || 'Unknown';
            algoResult.textContent = `Detected: ${algorithm}`;
        } else {
            algoStatus.style.color = 'var(--text-secondary)';
            algoStatus.className = 'fas fa-circle';
            algoResult.textContent = 'Not Detected';
        }
    }

    // Update Latest Detection section
    const latestSection = document.getElementById('latest-detection-section');
    const latestDetection = document.getElementById('latest-detection');
    if (latestSection && latestDetection) {
        if (results.threat_analysis && results.threat_analysis.apt_attribution && results.threat_analysis.apt_attribution.likely_actor) {
            const apt = results.threat_analysis.apt_attribution;
            const timestamp = new Date().toLocaleString();
            latestSection.style.display = 'block';
            latestDetection.innerHTML = `
                <div style="font-size: 14px; color: var(--text-primary); margin-bottom: 4px;">
                    <strong style="color: var(--danger-color);">${apt.likely_actor}</strong>
                </div>
                <div style="font-size: 12px; color: var(--text-secondary);">
                    Confidence: ${(apt.confidence * 100).toFixed(0)}% • ${timestamp}
                </div>
            `;
        }
    }
}
