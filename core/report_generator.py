"""
StegoGuard Pro - Professional Forensic Report Generator
Generates high-level professional reports in HTML and PDF formats
"""

from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
import json
import hashlib


class ForensicReportGenerator:
    """Professional forensic report generator for steganography analysis"""

    def __init__(self):
        self.report_id = None
        self.timestamp = None

    def generate_report_id(self) -> str:
        """Generate unique report ID: SG-YYYYMMDD-HHMM"""
        now = datetime.now()
        return f"SG-{now.strftime('%Y%m%d-%H%M')}"

    def generate_html_report(self, analysis_results: Dict) -> str:
        """Generate professional HTML forensic report"""

        self.report_id = self.generate_report_id()
        self.timestamp = datetime.now().strftime('%B %d, %Y %I:%M %p UTC')

        # Extract data
        file_info = analysis_results.get('file_info', {})
        metadata = analysis_results.get('metadata', {})
        detection_results = analysis_results.get('detection_results', [])
        decryption_results = analysis_results.get('decryption_results', {})
        threat_intel = analysis_results.get('threat_intel', {})

        # Generate SHA256 if not present
        sha256 = file_info.get('sha256', hashlib.sha256(str(analysis_results).encode()).hexdigest())

        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>StegoGuard Forensic Report - {self.report_id}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0a0e27;
            color: #e0e0e0;
            line-height: 1.6;
            padding: 40px 20px;
        }}

        .report-container {{
            max-width: 1200px;
            margin: 0 auto;
            background: linear-gradient(135deg, #0f1419 0%, #1a1f35 100%);
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 10px 50px rgba(0, 0, 0, 0.5);
        }}

        .report-header {{
            background: linear-gradient(135deg, #00e5ff 0%, #0091ea 100%);
            padding: 40px;
            text-align: center;
            border-bottom: 4px solid #00e5ff;
        }}

        .report-header h1 {{
            font-size: 32px;
            font-weight: 700;
            color: #0a0e27;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 2px;
        }}

        .report-meta {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 10px;
            margin-top: 20px;
        }}

        .report-meta-item {{
            background: rgba(10, 14, 39, 0.5);
            padding: 10px;
            border-radius: 6px;
            color: #fff;
            font-size: 13px;
        }}

        .report-meta-item strong {{
            display: block;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 5px;
            opacity: 0.7;
        }}

        .report-body {{
            padding: 40px;
        }}

        .section {{
            margin-bottom: 40px;
            background: rgba(255, 255, 255, 0.02);
            padding: 30px;
            border-radius: 8px;
            border-left: 4px solid #00e5ff;
        }}

        .section-header {{
            display: flex;
            align-items: center;
            margin-bottom: 25px;
            padding-bottom: 15px;
            border-bottom: 2px solid rgba(0, 229, 255, 0.2);
        }}

        .section-header h2 {{
            font-size: 24px;
            font-weight: 600;
            color: #00e5ff;
            display: flex;
            align-items: center;
            gap: 12px;
        }}

        .section-icon {{
            font-size: 28px;
        }}

        .info-grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 20px;
        }}

        .info-item {{
            background: rgba(0, 229, 255, 0.05);
            padding: 15px;
            border-radius: 6px;
            border: 1px solid rgba(0, 229, 255, 0.1);
        }}

        .info-item .label {{
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #00e5ff;
            margin-bottom: 8px;
            font-weight: 600;
        }}

        .info-item .value {{
            font-size: 15px;
            color: #fff;
            word-break: break-all;
        }}

        .threat-badge {{
            display: inline-block;
            padding: 8px 20px;
            border-radius: 20px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-size: 14px;
            margin: 10px 0;
        }}

        .threat-critical {{
            background: #ef4444;
            color: #fff;
            box-shadow: 0 0 20px rgba(239, 68, 68, 0.5);
        }}

        .threat-high {{
            background: #f97316;
            color: #fff;
            box-shadow: 0 0 20px rgba(249, 115, 22, 0.5);
        }}

        .threat-medium {{
            background: #eab308;
            color: #000;
            box-shadow: 0 0 20px rgba(234, 179, 8, 0.5);
        }}

        .threat-low {{
            background: #22c55e;
            color: #fff;
            box-shadow: 0 0 20px rgba(34, 197, 94, 0.5);
        }}

        .detection-list {{
            list-style: none;
        }}

        .detection-item {{
            background: rgba(0, 229, 255, 0.03);
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 8px;
            border-left: 4px solid #00e5ff;
            transition: all 0.3s;
        }}

        .detection-item:hover {{
            background: rgba(0, 229, 255, 0.08);
            transform: translateX(5px);
        }}

        .detection-item.detected {{
            border-left-color: #ef4444;
        }}

        .detection-item.clean {{
            border-left-color: #22c55e;
        }}

        .detection-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
        }}

        .detection-name {{
            font-size: 18px;
            font-weight: 600;
            color: #fff;
        }}

        .detection-status {{
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .status-icon {{
            font-size: 20px;
        }}

        .status-detected {{
            color: #ef4444;
        }}

        .status-clean {{
            color: #22c55e;
        }}

        .detection-details {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid rgba(0, 229, 255, 0.1);
        }}

        .detail-item {{
            font-size: 13px;
        }}

        .detail-label {{
            color: #00e5ff;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 11px;
            letter-spacing: 1px;
            margin-bottom: 5px;
        }}

        .detail-value {{
            color: #fff;
        }}

        .description {{
            margin-top: 12px;
            padding: 12px;
            background: rgba(0, 0, 0, 0.3);
            border-radius: 6px;
            font-size: 14px;
            line-height: 1.5;
            color: #e0e0e0;
        }}

        .probe-list {{
            list-style: none;
        }}

        .probe-item {{
            background: rgba(0, 229, 255, 0.05);
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
            border: 1px solid rgba(0, 229, 255, 0.2);
        }}

        .probe-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}

        .probe-name {{
            font-size: 18px;
            font-weight: 600;
            color: #00e5ff;
        }}

        .probe-result {{
            padding: 5px 15px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }}

        .probe-success {{
            background: #22c55e;
            color: #fff;
        }}

        .probe-partial {{
            background: #eab308;
            color: #000;
        }}

        .probe-failed {{
            background: #ef4444;
            color: #fff;
        }}

        .probe-details {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
            margin-top: 15px;
        }}

        .extracted-data {{
            margin-top: 15px;
            padding: 15px;
            background: rgba(0, 0, 0, 0.4);
            border-radius: 6px;
            border: 1px solid rgba(0, 229, 255, 0.3);
        }}

        .extracted-data-label {{
            color: #00e5ff;
            font-weight: 600;
            margin-bottom: 10px;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}

        .extracted-data-content {{
            font-family: 'Courier New', monospace;
            color: #22c55e;
            font-size: 14px;
            line-height: 1.8;
            word-break: break-all;
        }}

        .progress-bar {{
            height: 30px;
            background: rgba(0, 0, 0, 0.3);
            border-radius: 15px;
            overflow: hidden;
            margin: 15px 0;
        }}

        .progress-fill {{
            height: 100%;
            background: linear-gradient(90deg, #00e5ff 0%, #0091ea 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            color: #fff;
            font-weight: 700;
            font-size: 14px;
            transition: width 0.5s;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin: 20px 0;
        }}

        .stat-card {{
            background: rgba(0, 229, 255, 0.05);
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border: 1px solid rgba(0, 229, 255, 0.2);
        }}

        .stat-value {{
            font-size: 32px;
            font-weight: 700;
            color: #00e5ff;
            margin-bottom: 8px;
        }}

        .stat-label {{
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #888;
        }}

        .alert-box {{
            background: rgba(239, 68, 68, 0.1);
            border: 2px solid #ef4444;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }}

        .alert-header {{
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 15px;
        }}

        .alert-icon {{
            font-size: 28px;
            color: #ef4444;
        }}

        .alert-title {{
            font-size: 20px;
            font-weight: 700;
            color: #ef4444;
            text-transform: uppercase;
        }}

        .alert-content {{
            color: #fff;
            line-height: 1.8;
            font-size: 15px;
        }}

        .recommendation {{
            background: rgba(0, 229, 255, 0.1);
            border-left: 4px solid #00e5ff;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }}

        .recommendation-title {{
            font-size: 16px;
            font-weight: 600;
            color: #00e5ff;
            margin-bottom: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}

        .recommendation-content {{
            color: #e0e0e0;
            line-height: 1.8;
        }}

        .footer {{
            background: rgba(0, 0, 0, 0.3);
            padding: 30px 40px;
            text-align: center;
            border-top: 2px solid rgba(0, 229, 255, 0.2);
        }}

        .footer-text {{
            color: #888;
            font-size: 13px;
        }}

        .footer-logo {{
            font-size: 24px;
            font-weight: 700;
            color: #00e5ff;
            margin-bottom: 10px;
            letter-spacing: 2px;
        }}

        @media print {{
            body {{
                background: #fff;
                color: #000;
            }}
            .report-container {{
                box-shadow: none;
            }}
        }}
    </style>
</head>
<body>
    <div class="report-container">
        <!-- Header -->
        <div class="report-header">
            <h1>🛡️ StegoGuard Forensic Report</h1>
            <div class="report-meta">
                <div class="report-meta-item">
                    <strong>Report ID</strong>
                    {self.report_id}
                </div>
                <div class="report-meta-item">
                    <strong>Generated</strong>
                    {self.timestamp}
                </div>
                <div class="report-meta-item">
                    <strong>Version</strong>
                    1.6 (Hardened Mode, Offline)
                </div>
            </div>
        </div>

        <!-- Body -->
        <div class="report-body">
            <!-- File Information Section -->
            <div class="section">
                <div class="section-header">
                    <h2><span class="section-icon">📄</span> File Information</h2>
                </div>
                <div class="info-grid">
                    <div class="info-item">
                        <div class="label">Filename</div>
                        <div class="value">{file_info.get('filename', 'unknown.png')}</div>
                    </div>
                    <div class="info-item">
                        <div class="label">SHA256 Hash</div>
                        <div class="value">{sha256[:40]}...</div>
                    </div>
                    <div class="info-item">
                        <div class="label">File Size</div>
                        <div class="value">{file_info.get('size', 0) / (1024*1024):.2f} MB</div>
                    </div>
                    <div class="info-item">
                        <div class="label">Dimensions</div>
                        <div class="value">{metadata.get('dimensions', 'N/A')}</div>
                    </div>
                    <div class="info-item">
                        <div class="label">Format</div>
                        <div class="value">{metadata.get('format', 'Unknown')}</div>
                    </div>
                    <div class="info-item">
                        <div class="label">Color Mode</div>
                        <div class="value">{metadata.get('color_mode', 'N/A')}</div>
                    </div>
                </div>

                {self._generate_exif_section(metadata)}
            </div>

            <!-- Threat Assessment Section -->
            <div class="section">
                <div class="section-header">
                    <h2><span class="section-icon">⚠️</span> Threat Assessment</h2>
                </div>

                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-value">{analysis_results.get('threat_level', 'UNKNOWN').upper()}</div>
                        <div class="stat-label">Threat Level</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{int(analysis_results.get('confidence', 0) * 100)}%</div>
                        <div class="stat-label">Confidence</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{analysis_results.get('anomaly_count', 0)}</div>
                        <div class="stat-label">Anomalies</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{int(analysis_results.get('detection_score', 0) * 100)}%</div>
                        <div class="stat-label">Detection Score</div>
                    </div>
                </div>

                {self._generate_threat_alert(analysis_results, threat_intel)}
            </div>

            <!-- Detection Breakdown Section -->
            <div class="section">
                <div class="section-header">
                    <h2><span class="section-icon">🔍</span> Detection Breakdown – All Anomalies</h2>
                </div>

                <ul class="detection-list">
                    {self._generate_detection_items(detection_results)}
                </ul>
            </div>

            <!-- Decryption Report Section -->
            {self._generate_decryption_section(decryption_results)}

            <!-- APT Attribution Section -->
            {self._generate_apt_section(threat_intel)}

            <!-- Recommendations Section -->
            <div class="section">
                <div class="section-header">
                    <h2><span class="section-icon">💡</span> Recommendations</h2>
                </div>

                {self._generate_recommendations(analysis_results, threat_intel)}
            </div>
        </div>

        <!-- Footer -->
        <div class="footer">
            <div class="footer-logo">STEGOGUARD PRO</div>
            <div class="footer-text">
                Advanced Steganography Detection & Analysis System<br>
                Generated by StegoGuard V2.7 | Confidential - Handle with Care
            </div>
        </div>
    </div>
</body>
</html>
"""
        return html

    def _generate_exif_section(self, metadata: Dict) -> str:
        """Generate EXIF data section"""
        if not metadata:
            return ""

        return f"""
                <div style="margin-top: 20px; padding: 15px; background: rgba(0, 0, 0, 0.2); border-radius: 6px;">
                    <div class="label" style="margin-bottom: 10px;">EXIF Metadata</div>
                    <div style="font-size: 13px; line-height: 1.8; color: #e0e0e0;">
                        <strong>Created:</strong> {metadata.get('DateTime', 'N/A')}<br>
                        <strong>Device:</strong> {metadata.get('Make', 'Unknown')} {metadata.get('Model', '')}<br>
                        <strong>GPS:</strong> {metadata.get('GPSLatitude', 'N/A')}, {metadata.get('GPSLongitude', 'N/A')}<br>
                        <strong>Software:</strong> {metadata.get('software', metadata.get('Software', 'N/A'))}
                    </div>
                </div>
        """

    def _generate_detection_items(self, detection_results: List[Dict]) -> str:
        """Generate detection items HTML"""
        items_html = ""

        for detection in detection_results:
            detected = detection.get('detected', False)
            status_class = 'detected' if detected else 'clean'
            status_icon = '⚠️' if detected else '✅'
            status_text_class = 'status-detected' if detected else 'status-clean'

            confidence = int(detection.get('confidence', 0) * 100)
            severity = detection.get('severity', 'unknown')

            items_html += f"""
                    <li class="detection-item {status_class}">
                        <div class="detection-header">
                            <span class="detection-name">{detection.get('detector', 'Unknown Detector')}</span>
                            <div class="detection-status">
                                <span class="status-icon {status_text_class}">{status_icon}</span>
                                <span style="color: #888; font-size: 14px;">
                                    {'DETECTED' if detected else 'CLEAN'}
                                </span>
                            </div>
                        </div>
                        <div class="detection-details">
                            <div class="detail-item">
                                <div class="detail-label">Confidence</div>
                                <div class="detail-value">{confidence}%</div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-label">Severity</div>
                                <div class="detail-value" style="text-transform: uppercase;">{severity}</div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-label">Type</div>
                                <div class="detail-value">{detection.get('type', 'N/A')}</div>
                            </div>
                        </div>
                        <div class="description">
                            {detection.get('details', 'No additional details available.')}
                        </div>
                    </li>
            """

        return items_html if items_html else '<li style="text-align: center; padding: 40px; color: #888;">No detection results available</li>'

    def _generate_decryption_section(self, decryption_results: Dict) -> str:
        """Generate decryption report section"""
        if not decryption_results or not decryption_results.get('activated'):
            return ""

        probes = decryption_results.get('probes', [])
        overall_success = decryption_results.get('overall_success_rate', 0)

        probes_html = ""
        for probe in probes:
            result_class = 'probe-success' if probe.get('success') else 'probe-partial' if probe.get('partial_success') else 'probe-failed'
            result_text = 'SUCCESS' if probe.get('success') else 'PARTIAL' if probe.get('partial_success') else 'FAILED'

            probes_html += f"""
                    <li class="probe-item">
                        <div class="probe-header">
                            <span class="probe-name">{probe.get('name', 'Unknown Probe')}</span>
                            <span class="probe-result {result_class}">{result_text}</span>
                        </div>
                        <div class="probe-details">
                            <div class="info-item">
                                <div class="label">Source</div>
                                <div class="value">{probe.get('source', 'N/A')}</div>
                            </div>
                            <div class="info-item">
                                <div class="label">Confidence</div>
                                <div class="value">{int(probe.get('confidence', 0) * 100)}%</div>
                            </div>
                        </div>
                        {self._generate_extracted_data(probe.get('extracted', ''))}
                    </li>
            """

        return f"""
            <div class="section">
                <div class="section-header">
                    <h2><span class="section-icon">🔐</span> Decryption Report – Full Chain</h2>
                </div>

                <div class="progress-bar">
                    <div class="progress-fill" style="width: {int(overall_success * 100)}%;">
                        {int(overall_success * 100)}% Success Rate
                    </div>
                </div>

                <ul class="probe-list">
                    {probes_html}
                </ul>

                <div class="info-grid" style="margin-top: 20px;">
                    <div class="info-item">
                        <div class="label">Overall Decryption</div>
                        <div class="value">{int(overall_success * 100)}% success</div>
                    </div>
                    <div class="info-item">
                        <div class="label">Time Taken</div>
                        <div class="value">{decryption_results.get('time_taken', 0)} seconds</div>
                    </div>
                </div>
            </div>
        """

    def _generate_extracted_data(self, data: str) -> str:
        """Generate extracted data display"""
        if not data:
            return ""

        return f"""
                        <div class="extracted-data">
                            <div class="extracted-data-label">Extracted Data:</div>
                            <div class="extracted-data-content">{data}</div>
                        </div>
        """

    def _generate_threat_alert(self, analysis: Dict, threat_intel: Dict) -> str:
        """Generate threat alert box"""
        threat_level = analysis.get('threat_level', 'unknown').upper()
        steganography_detected = analysis.get('steganography_detected', False)

        if threat_level in ['CRITICAL', 'HIGH'] or steganography_detected:
            apt_match = threat_intel.get('apt_match', 'Unknown')

            return f"""
                <div class="alert-box">
                    <div class="alert-header">
                        <span class="alert-icon">🚨</span>
                        <span class="alert-title">THREAT DETECTED</span>
                    </div>
                    <div class="alert-content">
                        <strong>Covert channel confirmed.</strong> The analyzed file contains multiple indicators of steganographic content.
                        {'<br><br><strong>Potential APT Attribution:</strong> ' + apt_match if apt_match != 'Unknown' else ''}
                        <br><br><strong>Action Required:</strong> Escalate to full forensics team for detailed analysis.
                    </div>
                </div>
            """

        return ""

    def _generate_apt_section(self, threat_intel: Dict) -> str:
        """Generate APT attribution section"""
        if not threat_intel or not threat_intel.get('apt_match'):
            return ""

        apt_name = threat_intel.get('apt_match', 'Unknown')
        confidence = int(threat_intel.get('confidence', 0) * 100)
        techniques = threat_intel.get('techniques', [])
        iocs = threat_intel.get('iocs', [])

        techniques_html = '<br>'.join([f"• {t}" for t in techniques])
        iocs_html = '<br>'.join([f"• {ioc}" for ioc in iocs])

        return f"""
            <div class="section">
                <div class="section-header">
                    <h2><span class="section-icon">🎯</span> APT Attribution Analysis</h2>
                </div>

                <div class="info-grid">
                    <div class="info-item">
                        <div class="label">APT Group</div>
                        <div class="value" style="font-size: 20px; font-weight: 700; color: #ef4444;">{apt_name}</div>
                    </div>
                    <div class="info-item">
                        <div class="label">Attribution Confidence</div>
                        <div class="value" style="font-size: 20px; font-weight: 700;">{confidence}%</div>
                    </div>
                </div>

                <div style="margin-top: 20px;">
                    <div class="info-item">
                        <div class="label">Known Techniques</div>
                        <div class="value" style="line-height: 1.8;">{techniques_html}</div>
                    </div>
                </div>

                <div style="margin-top: 20px;">
                    <div class="info-item">
                        <div class="label">Indicators of Compromise (IOCs)</div>
                        <div class="value" style="line-height: 1.8;">{iocs_html}</div>
                    </div>
                </div>
            </div>
        """

    def _generate_recommendations(self, analysis: Dict, threat_intel: Dict) -> str:
        """Generate recommendations"""
        threat_level = analysis.get('threat_level', 'unknown').upper()

        recommendations = []

        if threat_level in ['CRITICAL', 'HIGH']:
            recommendations.append("🔴 <strong>CRITICAL:</strong> Isolate the file and source system immediately.")
            recommendations.append("🔴 Forward all extracted data to cryptanalysis team for pattern analysis.")
            recommendations.append("🔴 Initiate incident response procedures and notify security operations center.")

        if threat_intel.get('apt_match'):
            recommendations.append(f"⚠️ Cross-reference findings with known {threat_intel.get('apt_match')} campaigns.")
            recommendations.append("⚠️ Review network traffic logs for exfiltration patterns.")

        if analysis.get('steganography_detected'):
            recommendations.append("🔍 Conduct deep packet inspection on all related network traffic.")
            recommendations.append("🔍 Analyze similar files from the same source for additional payloads.")

        recommendations.append("📋 Document all findings in the incident management system.")
        recommendations.append("📋 Preserve original file and all analysis artifacts for legal evidence.")

        rec_html = '<br><br>'.join(recommendations)

        return f"""
                <div class="recommendation-content">
                    {rec_html}
                </div>
        """

    def save_html_report(self, html_content: str, output_path: Path) -> Path:
        """Save HTML report to file"""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return output_path

    def generate_text_report(self, analysis_results: Dict) -> str:
        """Generate professional text-based forensic report"""

        self.report_id = self.generate_report_id()
        self.timestamp = datetime.now().strftime('%B %d, %Y %I:%M %p UTC')

        file_info = analysis_results.get('file_info', {})
        metadata = analysis_results.get('metadata', {})
        detection_results = analysis_results.get('detection_results', [])
        threat_intel = analysis_results.get('threat_intel', {})

        sha256 = file_info.get('sha256', hashlib.sha256(str(analysis_results).encode()).hexdigest())

        report = f"""
╔══════════════════════════════════════════════════════════════════════════╗
║                    STEGOGUARD FORENSIC REPORT                           ║
╚══════════════════════════════════════════════════════════════════════════╝

Report ID: {self.report_id}
Generated: {self.timestamp}
Version: 1.6 (Hardened Mode, Offline)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FILE INFORMATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

File Analyzed: {file_info.get('filename', 'unknown.png')}
SHA256: {sha256}
Size: {file_info.get('size', 0) / (1024*1024):.2f} MB
Dimensions: {metadata.get('dimensions', 'N/A')}
Format: {metadata.get('format', 'Unknown')}

EXIF Data:
  Created: {metadata.get('DateTime', 'N/A')}
  Device: {metadata.get('Make', 'Unknown')} {metadata.get('Model', '')}
  GPS: {metadata.get('GPSLatitude', 'N/A')}, {metadata.get('GPSLongitude', 'N/A')}
  Software: {metadata.get('software', metadata.get('Software', 'N/A'))}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
THREAT ASSESSMENT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Threat Level: {analysis_results.get('threat_level', 'UNKNOWN').upper()}
Confidence: {int(analysis_results.get('confidence', 0) * 100)}%
Anomaly Count: {analysis_results.get('anomaly_count', 0)}
Detection Score: {int(analysis_results.get('detection_score', 0) * 100)}%
Steganography Detected: {analysis_results.get('steganography_detected', False)}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DETECTION BREAKDOWN – ALL ANOMALIES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

        for detection in detection_results:
            detected = detection.get('detected', False)
            status = '⚠️  DETECTED' if detected else '✅ CLEAN'

            report += f"""
{detection.get('detector', 'Unknown Detector')}
  Status: {status}
  Confidence: {int(detection.get('confidence', 0) * 100)}%
  Severity: {detection.get('severity', 'unknown').upper()}
  Details: {detection.get('details', 'No details available')}

"""

        if threat_intel.get('apt_match'):
            report += f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
APT ATTRIBUTION ANALYSIS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

APT Group: {threat_intel.get('apt_match', 'Unknown')}
Attribution Confidence: {int(threat_intel.get('confidence', 0) * 100)}%

Known Techniques:
"""
            for tech in threat_intel.get('techniques', []):
                report += f"  • {tech}\n"

            report += "\nIndicators of Compromise (IOCs):\n"
            for ioc in threat_intel.get('iocs', []):
                report += f"  • {ioc}\n"

        report += f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FINAL ASSESSMENT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Threat: {analysis_results.get('threat_level', 'UNKNOWN').upper()}
Actor: {'Active' if threat_intel.get('apt_match') else 'Unknown'}
Covert channel: {'Confirmed' if analysis_results.get('steganography_detected') else 'Not detected'}

RECOMMENDATIONS:
• Escalate to full forensics team for detailed analysis
• Isolate affected systems and files
• Review network traffic logs for exfiltration patterns
• Document all findings in incident management system
• Preserve original file for legal evidence

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Generated by StegoGuard Pro V2.7
Confidential - Handle with Care

"""
        return report
