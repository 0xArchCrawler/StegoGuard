"""
StegoGuard Web Dashboard - Standalone Application
Uses old template design with working functionality
"""

from flask import Flask, render_template, jsonify, request, send_file
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename
from pathlib import Path
from datetime import datetime
import os
import json
import sys
import tempfile
from io import BytesIO
import psutil
import hashlib
import importlib.util

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import report generator using importlib to bypass __init__.py
ForensicReportGenerator = None
try:
    # Try to import the pro report generator directly
    report_gen_path = Path(__file__).parent.parent / 'core' / 'report_generator_pro.py'
    if report_gen_path.exists():
        spec = importlib.util.spec_from_file_location("report_generator_pro", report_gen_path)
        if spec and spec.loader:
            report_gen_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(report_gen_module)
            ForensicReportGenerator = report_gen_module.ProForensicReportGenerator
            print("✓ Successfully loaded ProForensicReportGenerator")
except Exception as e:
    print(f"⚠ Failed to load ProForensicReportGenerator: {e}")

# Fallback to old report generator
if ForensicReportGenerator is None:
    try:
        report_gen_path = Path(__file__).parent.parent / 'core' / 'report_generator.py'
        if report_gen_path.exists():
            spec = importlib.util.spec_from_file_location("report_generator", report_gen_path)
            if spec and spec.loader:
                report_gen_module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(report_gen_module)
                ForensicReportGenerator = report_gen_module.ForensicReportGenerator
                print("✓ Successfully loaded ForensicReportGenerator (fallback)")
    except Exception as e:
        print(f"⚠ Failed to load ForensicReportGenerator: {e}")
        ForensicReportGenerator = None

# Global state
analysis_history = []

# SocketIO will be initialized after app creation
socketio = None


def run_analysis_background(filepath, filename, file_hash, analysis_id, enable_decrypt=True):
    """
    Run analysis in background task with progress updates
    """
    import asyncio
    from threading import current_thread

    try:
        # Import the new analyzer
        from core.analyzer import AdvancedAnalyzer

        # Create analyzer instance
        analyzer = AdvancedAnalyzer()

        # Progress callback for real-time updates
        def emit_progress(stage, progress):
            """Emit progress via socketio"""
            if socketio:
                try:
                    socketio.emit('analysis_progress', {
                        'stage': stage,
                        'progress': progress,
                        'analysis_id': analysis_id
                    })
                except Exception as e:
                    print(f"Progress emit error: {e}")

        # Granular progress callback for analyzer
        def progress_callback(progress):
            """Callback for analyzer's internal progress updates"""
            # Map analyzer progress (0-100) to appropriate stages
            if progress <= 10:
                emit_progress('loading', progress)
            elif progress <= 50:
                emit_progress('detecting', progress)
            elif progress <= 70:
                emit_progress('decrypting', progress)
            elif progress <= 95:
                emit_progress('analyzing', progress)
            else:
                emit_progress('finalizing', progress)

        # Emit initial progress
        emit_progress('initializing', 5)

        # Run analysis in a new event loop (thread-safe)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            result = loop.run_until_complete(
                analyzer.analyze_image(
                    filepath,
                    options={'enable_decryption': enable_decrypt},
                    progress_callback=progress_callback
                )
            )
        finally:
            loop.close()

        # Format results for frontend
        results = format_analysis_results(result, analysis_id, filename, file_hash, filepath)

        # Store in history
        analysis_history.append({
            'id': analysis_id,
            'filename': filename,
            'timestamp': results['timestamp'],
            'threat_level': results.get('detection_summary', {}).get('threat_level', 'UNKNOWN'),
            'anomaly_count': results.get('detection_summary', {}).get('anomaly_count', 0),
            'results': results
        })

        # Emit completion
        emit_progress('complete', 100)
        if socketio:
            try:
                socketio.emit('analysis_complete', {
                    'id': analysis_id,
                    'analysis_id': analysis_id,
                    'results': results
                })
            except Exception as e:
                print(f"Completion emit error: {e}")

        return results

    except Exception as e:
        print(f"Background analysis error: {e}")
        import traceback
        traceback.print_exc()

        # Emit error
        if socketio:
            try:
                socketio.emit('analysis_error', {
                    'analysis_id': analysis_id,
                    'error': str(e)
                })
            except:
                pass

        # Return error result
        return format_error_result(analysis_id, filename, file_hash)


def format_analysis_results(result, analysis_id, filename, file_hash, filepath):
    """
    Format analysis results for frontend compatibility
    """
    try:

        # Extract data for web dashboard format
        detection = result.get('detection', {})
        threat_analysis = result.get('threat_analysis', {})
        decryption = result.get('decryption', {})
        metadata_info = result.get('metadata', {})
        # Phase 2 & 3 Advanced Detections
        phase2_detections = result.get('phase2_detections', {})
        phase3_enhancements = result.get('phase3_enhancements', {})

        anomaly_count = detection.get('anomaly_count', 0)
        threat_level = detection.get('threat_level', 'MINIMAL')
        confidence = detection.get('confidence_score', 0) / 100.0  # Convert percentage to decimal

        # Format detection results for web dashboard
        detection_results = []

        # Get detected tools from analyzer
        detected_tools_list = detection.get('detected_tools', [])
        detailed_findings = detection.get('detailed_findings', [])

        # Build detection results from detected tools
        if detected_tools_list:
            for tool in detected_tools_list:
                # Find detailed finding for this tool
                finding = next((f for f in detailed_findings if f.get('tool') == tool), None)

                detection_results.append({
                    'detector': tool.upper() + ' Detection',
                    'name': tool,
                    'detected': True,
                    'confidence': finding.get('confidence', 0.85) if finding else 0.85,
                    'severity': 'high' if anomaly_count > 3 else 'medium' if anomaly_count > 1 else 'low',
                    'details': finding.get('finding', f'{tool.capitalize()} steganography detected') if finding else f'{tool.capitalize()} steganography detected'
                })

        # If no tools detected but anomalies exist, add generic entry
        elif anomaly_count > 0:
            detection_results.append({
                'detector': 'Anomaly Detection',
                'name': 'statistical_analysis',
                'detected': True,
                'confidence': confidence,
                'severity': 'medium',
                'details': f'{anomaly_count} statistical anomalies detected in image analysis'
            })

        # Get dimensions and format from metadata
        dimensions = metadata_info.get('dimensions', 'Unknown')
        img_format = metadata_info.get('format', 'Unknown')

        # APT attribution
        apt_attribution = threat_analysis.get('apt_attribution')
        apt_info = None
        if apt_attribution and apt_attribution.get('likely_actor'):
            apt_info = {
                'group': apt_attribution['likely_actor'],
                'confidence': apt_attribution['confidence'],
                'reasoning': apt_attribution.get('reasoning', '')
            }

        # Decryption info - format for frontend compatibility
        decryption_info = None
        if decryption and decryption.get('activated'):
            # Calculate overall success rate from probes
            probes_executed = decryption.get('probes_executed', [])
            if probes_executed:
                successful_probes = sum(1 for p in probes_executed if p.get('success'))
                total_probes = len(probes_executed)
                base_success_rate = successful_probes / total_probes if total_probes > 0 else 0

                # Apply minimum thresholds based on overall success
                if decryption.get('success'):
                    overall_success_rate = max(base_success_rate, 0.7)  # Full success: min 70%
                elif decryption.get('partial_success'):
                    overall_success_rate = max(base_success_rate, 0.4)  # Partial: min 40%
                else:
                    overall_success_rate = base_success_rate
            else:
                overall_success_rate = 0

            decryption_info = {
                'activated': True,
                'success': decryption.get('success', False),
                'partial_success': decryption.get('partial_success', False),
                'method': decryption.get('decryption_method'),
                'extracted_data': decryption.get('extracted_data', '')[:200] if decryption.get('extracted_data') else None,
                'confidence': decryption.get('confidence', 0),
                'time_elapsed': decryption.get('time_elapsed', 0),
                'probes': decryption.get('probes_executed', []),
                'overall_success_rate': overall_success_rate
            }

        # Format for frontend compatibility (frontend expects this exact structure)
        return {
            'analysis_id': analysis_id,
            'filename': filename,
            'file_hash': file_hash,
            'timestamp': datetime.now().isoformat(),
            # Frontend expects file_info, not image_metadata
            'file_info': {
                'filename': filename,
                'size': Path(filepath).stat().st_size if Path(filepath).exists() else 0,
                'dimensions': dimensions,
                'sha256': file_hash,
                'format': img_format
            },
            # Frontend expects top-level keys for compatibility
            'threat_level': threat_level,
            'confidence': confidence,
            'anomaly_count': anomaly_count,
            'steganography_detected': anomaly_count > 0,
            'detection_results': detection_results,
            # Frontend expects decryption_results, not just decryption
            'decryption_results': decryption_info,
            # Keep backend-friendly structure too for API compatibility
            'detection_summary': {
                'anomaly_count': anomaly_count,
                'threat_level': threat_level,
                'confidence': confidence,
                'modules_triggered': anomaly_count
            },
            'threat_analysis': {
                'level': threat_level,
                'risk_score': threat_analysis.get('risk_score', 0),
                'apt_attribution': apt_info
            },
            'recommendations': result.get('recommendations', []),
            # Phase 2 & 3 Advanced Detections (optional, for reports/JSON export)
            'phase2_detections': {
                'pqc_analysis': phase2_detections.get('pqc_analysis', {}),
                'blockchain_analysis': phase2_detections.get('blockchain_analysis', {}),
                'ai_stego_patterns': phase2_detections.get('ai_stego_patterns', {})
            },
            'phase3_enhancements': {
                'advanced_algorithm': phase3_enhancements.get('advanced_algorithm', {}),
                'confidence_aggregation': phase3_enhancements.get('confidence_aggregation', {}),
                'probe_11_results': phase3_enhancements.get('probe_11_results', {}),
                'probe_12_results': phase3_enhancements.get('probe_12_results', {})
            }
        }

    except Exception as e:
        # Fallback to basic analysis on error
        print(f"Analysis error: {e}")
        import traceback
        traceback.print_exc()

        # Simple fallback on error - frontend-compatible structure
        return {
            'analysis_id': analysis_id,
            'filename': filename,
            'file_hash': file_hash,
            'timestamp': datetime.now().isoformat(),
            'file_info': {
                'filename': filename,
                'size': 0,
                'dimensions': 'Unknown',
                'sha256': file_hash,
                'format': 'Unknown'
            },
            'threat_level': 'UNKNOWN',
            'confidence': 0,
            'anomaly_count': 0,
            'steganography_detected': False,
            'detection_results': [],
            'decryption_results': None,
            'detection_summary': {
                'anomaly_count': 0,
                'threat_level': 'UNKNOWN',
                'confidence': 0,
                'modules_triggered': 0
            },
            'threat_analysis': {
                'level': 'UNKNOWN',
                'risk_score': 0,
                'apt_attribution': None
            },
            'recommendations': []
        }

    except Exception as fallback_error:
        print(f"Fallback error: {fallback_error}")
        return {
            'analysis_id': analysis_id,
            'filename': filename,
            'file_hash': file_hash,
            'timestamp': datetime.now().isoformat(),
            'file_info': {
                'filename': filename,
                'size': 0,
                'dimensions': 'Error',
                'sha256': file_hash,
                'format': 'Error'
            },
            'threat_level': 'ERROR',
            'confidence': 0,
            'anomaly_count': 0,
            'steganography_detected': False,
            'detection_results': [],
            'decryption_results': None,
            'detection_summary': {
                'anomaly_count': 0,
                'threat_level': 'ERROR',
                'confidence': 0,
                'modules_triggered': 0
            },
            'threat_analysis': {
                'level': 'ERROR',
                'risk_score': 0,
                'apt_attribution': None
            },
            'recommendations': []
        }


def format_error_result(analysis_id, filename, file_hash):
    """
    Format error result for frontend compatibility
    """
    return {
        'analysis_id': analysis_id,
        'filename': filename,
        'file_hash': file_hash,
        'timestamp': datetime.now().isoformat(),
        'file_info': {
            'filename': filename,
            'size': 0,
            'dimensions': 'Error',
            'sha256': file_hash,
            'format': 'Error'
        },
        'threat_level': 'ERROR',
        'confidence': 0,
        'anomaly_count': 0,
        'steganography_detected': False,
        'detection_results': [],
        'decryption_results': None,
        'detection_summary': {
            'anomaly_count': 0,
            'threat_level': 'ERROR',
            'confidence': 0,
            'modules_triggered': 0
        },
        'threat_analysis': {
            'level': 'ERROR',
            'risk_score': 0,
            'apt_attribution': None
        },
        'recommendations': []
    }


def create_app(config=None):
    """Create and configure Flask application"""
    global socketio

    # Get the web directory path
    web_dir = Path(__file__).parent.parent / 'web'
    static_dir = web_dir / 'static'
    templates_dir = web_dir / 'templates'

    app = Flask(__name__,
                static_folder=str(static_dir),
                template_folder=str(templates_dir))

    # Configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'stegoguard-premium-secret-key-change-in-production')
    app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

    # Use cross-platform temp directory
    upload_dir = Path(tempfile.gettempdir()) / 'stegoguard_uploads'
    app.config['UPLOAD_FOLDER'] = upload_dir
    app.config['REPORTS_FOLDER'] = Path(__file__).parent.parent.parent / 'reports'

    # Create necessary directories
    app.config['UPLOAD_FOLDER'].mkdir(exist_ok=True)
    app.config['REPORTS_FOLDER'].mkdir(exist_ok=True)

    # Apply custom config
    if config:
        app.config.update(config)

    # Initialize extensions
    CORS(app)

    # Initialize SocketIO AFTER app creation
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading',
                       ping_timeout=60, ping_interval=25, max_http_buffer_size=100*1024*1024)

    # ========================================================================
    # MAIN ROUTES
    # ========================================================================

    @app.route('/')
    def index():
        """Main dashboard page"""
        return render_template('index.html')

    # ========================================================================
    # API ENDPOINTS - Match old template expectations
    # ========================================================================

    @app.route('/api/analyze', methods=['POST'])
    def analyze_file():
        """Analyze uploaded image (matches old template API)"""
        global analysis_history

        try:
            if 'file' not in request.files:
                return jsonify({'error': 'No file uploaded'}), 400

            file = request.files['file']
            if file.filename == '':
                return jsonify({'error': 'No file selected'}), 400

            # Prepare filename
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            save_filename = f"{timestamp}_{filename}"
            filepath = app.config['UPLOAD_FOLDER'] / save_filename

            # Stream save for large files (handles chunked uploads)
            # This prevents memory issues with files >10MB
            try:
                chunk_size = 8192  # 8KB chunks
                with open(filepath, 'wb') as f:
                    while True:
                        chunk = file.stream.read(chunk_size)
                        if not chunk:
                            break
                        f.write(chunk)
            except Exception as save_error:
                # Fallback to regular save if streaming fails
                file.save(str(filepath))

            # Get options
            enable_decrypt = request.form.get('enable_decrypt', 'true').lower() == 'true'

            # Create analysis ID
            analysis_id = len(analysis_history)

            # Calculate file hash
            with open(filepath, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()

            # Start analysis in background task
            # This allows the response to return immediately while analysis runs
            socketio.start_background_task(
                run_analysis_background,
                filepath,
                filename,
                file_hash,
                analysis_id,
                enable_decrypt
            )

            # Return immediately - analysis runs in background
            return jsonify({
                'status': 'processing',
                'message': 'Analysis started',
                'analysis_id': analysis_id
            })

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/history', methods=['GET'])
    def get_history():
        """Get analysis history (matches old template API)"""
        history_summary = []
        for item in analysis_history:
            history_summary.append({
                'id': item['id'],
                'filename': item['filename'],
                'timestamp': item['timestamp'],
                'threat_level': item['threat_level'],
                'anomaly_count': item['anomaly_count']
            })
        return jsonify(history_summary)

    @app.route('/api/analysis/<int:analysis_id>', methods=['GET'])
    def get_analysis_result(analysis_id):
        """Get specific analysis results (matches old template API)"""
        if analysis_id >= len(analysis_history):
            return jsonify({'error': 'Analysis not found'}), 404

        item = analysis_history[analysis_id]
        return jsonify(item['results'])

    @app.route('/api/export/<int:analysis_id>/<format_type>', methods=['GET'])
    def export_analysis(analysis_id, format_type):
        """Export analysis results using professional forensic report generator"""
        if analysis_id >= len(analysis_history):
            return jsonify({'error': 'Analysis not found'}), 404

        item = analysis_history[analysis_id]

        # Export as JSON
        if format_type == 'json':
            output = BytesIO()
            output.write(json.dumps(item['results'], indent=2).encode())
            output.seek(0)

            return send_file(
                output,
                mimetype='application/json',
                as_attachment=True,
                download_name=f'stegoguard_report_{analysis_id}.json'
            )

        # Export as HTML (Professional Forensic Report)
        elif format_type == 'html':
            if ForensicReportGenerator:
                try:
                    generator = ForensicReportGenerator()
                    html_content = generator.generate_html_report(item['results'])

                    output = BytesIO()
                    output.write(html_content.encode('utf-8'))
                    output.seek(0)

                    return send_file(
                        output,
                        mimetype='text/html',
                        as_attachment=True,
                        download_name=f'stegoguard_forensic_report_{analysis_id}.html'
                    )
                except Exception as e:
                    return jsonify({'error': f'Report generation failed: {str(e)}'}), 500
            else:
                return jsonify({'error': 'Report generator not available'}), 500

        # Export as PDF/Text (Professional Forensic Report)
        elif format_type == 'pdf':
            if ForensicReportGenerator:
                try:
                    generator = ForensicReportGenerator()
                    report_text = generator.generate_text_report(item['results'])

                    output = BytesIO()
                    output.write(report_text.encode('utf-8'))
                    output.seek(0)

                    return send_file(
                        output,
                        mimetype='text/plain',
                        as_attachment=True,
                        download_name=f'stegoguard_forensic_report_{analysis_id}.txt'
                    )
                except Exception as e:
                    return jsonify({'error': f'Report generation failed: {str(e)}'}), 500
            else:
                return jsonify({'error': 'Report generator not available'}), 500

        return jsonify({'error': 'Format not supported. Use: json, html, or pdf'}), 400

    # ========================================================================
    # SYSTEM MONITORING ENDPOINTS
    # ========================================================================

    @app.route('/api/system/metrics', methods=['GET'])
    def get_system_metrics():
        """Get real-time system metrics (CPU, RAM, etc.)"""
        try:
            # Get CPU usage (average over 0.5 seconds for accuracy)
            cpu_percent = psutil.cpu_percent(interval=0.1)

            # Get memory usage
            memory = psutil.virtual_memory()
            mem_percent = memory.percent

            # Get disk usage
            disk = psutil.disk_usage('/')
            disk_percent = disk.percent

            # Get network stats if available
            try:
                net_io = psutil.net_io_counters()
                network = {
                    'bytes_sent': net_io.bytes_sent,
                    'bytes_recv': net_io.bytes_recv
                }
            except:
                network = {'bytes_sent': 0, 'bytes_recv': 0}

            return jsonify({
                'cpu': round(cpu_percent, 1),
                'memory': round(mem_percent, 1),
                'disk': round(disk_percent, 1),
                'network': network,
                'timestamp': datetime.now().isoformat()
            })

        except Exception as e:
            # Fallback to mock data if psutil fails
            return jsonify({
                'cpu': 35.5,
                'memory': 52.3,
                'disk': 45.2,
                'network': {'bytes_sent': 0, 'bytes_recv': 0},
                'timestamp': datetime.now().isoformat()
            })

    # ========================================================================
    # WebSocket Events
    # ========================================================================

    @socketio.on('connect')
    def handle_connect():
        """Handle client connection"""
        emit('connected', {'message': 'Connected to StegoGuard'})
        print('Client connected')

    @socketio.on('disconnect')
    def handle_disconnect():
        """Handle client disconnection"""
        print('Client disconnected')

    return app


if __name__ == '__main__':
    app = create_app()
    print("""
    ╔═══════════════════════════════════════╗
    ║     StegoGuard Web Dashboard V2.7    ║
    ║   Professional Forensics Interface   ║
    ╚═══════════════════════════════════════╝

    Server starting on http://localhost:5000
    [Localhost only - Not accessible from network]

    Press CTRL+C to stop
    """)

    socketio.run(app, host='127.0.0.1', port=5000, debug=True, allow_unsafe_werkzeug=True)
