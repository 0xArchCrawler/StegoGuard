"""
StegoGuard API Routes
RESTful endpoints for all functionality
"""

from flask import Blueprint, request, jsonify, send_file
from werkzeug.utils import secure_filename
import asyncio
from pathlib import Path
import uuid
from datetime import datetime
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from api.app import socketio, limiter
from api.auth import require_auth, get_current_user
from core.analyzer import AdvancedAnalyzer
from core.job_manager import JobManager
from core.batch_processor import BatchProcessor
from core.file_upload_validator import FileUploadValidator

# Create blueprints
analysis_bp = Blueprint('analysis', __name__)
dashboard_bp = Blueprint('dashboard', __name__)
jobs_bp = Blueprint('jobs', __name__)
reports_bp = Blueprint('reports', __name__)
system_bp = Blueprint('system', __name__)

# Initialize managers
analyzer = AdvancedAnalyzer()
job_manager = JobManager()
batch_processor = BatchProcessor()


# ============================================================================
# ANALYSIS ENDPOINTS
# ============================================================================

@analysis_bp.route('/upload', methods=['POST'])
@limiter.limit("20 per hour")
def upload_file():
    """Upload image for analysis"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        # Validate file type
        allowed_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.tiff'}
        file_ext = Path(file.filename).suffix.lower()

        if file_ext not in allowed_extensions:
            return jsonify({'error': 'Invalid file type'}), 400

        # Save file
        filename = secure_filename(file.filename)
        file_id = str(uuid.uuid4())
        upload_path = Path(request.app.config['UPLOAD_FOLDER']) / f"{file_id}_{filename}"
        file.save(upload_path)

        # Validate uploaded file (magic bytes, size, integrity)
        validator = FileUploadValidator()
        validation_result = validator.validate(str(upload_path))

        if not validation_result['valid']:
            # Remove invalid file
            if upload_path.exists():
                upload_path.unlink()

            errors = ', '.join(validation_result['errors'])
            return jsonify({
                'error': f'File validation failed: {errors}'
            }), 400

        # Add validation info to response
        file_info = validation_result.get('file_info', {})

        return jsonify({
            'success': True,
            'file_id': file_id,
            'filename': filename,
            'path': str(upload_path),
            'validation': {
                'format': file_info.get('detected_format'),
                'size_mb': round(file_info.get('size_mb', 0), 2),
                'dimensions': f"{file_info.get('width')}x{file_info.get('height')}",
                'checksum': file_info.get('checksum', '')[:16]  # First 16 chars
            }
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@analysis_bp.route('/analyze', methods=['POST'])
@limiter.limit("10 per hour")
def analyze_image():
    """Start analysis of uploaded image"""
    try:
        data = request.get_json()
        file_path = data.get('file_path')
        options = data.get('options', {})

        if not file_path or not Path(file_path).exists():
            return jsonify({'error': 'Invalid file path'}), 400

        # Create analysis job
        job_id = str(uuid.uuid4())
        job = {
            'id': job_id,
            'file_path': file_path,
            'status': 'queued',
            'created_at': datetime.now().isoformat(),
            'options': options
        }

        # Queue job
        job_manager.add_job(job)

        # Start analysis in background
        socketio.start_background_task(run_analysis, job_id, file_path, options)

        return jsonify({
            'success': True,
            'job_id': job_id,
            'message': 'Analysis started'
        }), 202

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@analysis_bp.route('/status/<job_id>', methods=['GET'])
def get_analysis_status(job_id):
    """Get status of analysis job"""
    try:
        job = job_manager.get_job(job_id)

        if not job:
            return jsonify({'error': 'Job not found'}), 404

        return jsonify(job), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@analysis_bp.route('/results/<job_id>', methods=['GET'])
def get_analysis_results(job_id):
    """Get results of completed analysis"""
    try:
        job = job_manager.get_job(job_id)

        if not job:
            return jsonify({'error': 'Job not found'}), 404

        if job['status'] != 'completed':
            return jsonify({'error': 'Analysis not completed'}), 400

        return jsonify(job.get('results', {})), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@analysis_bp.route('/batch', methods=['POST'])
@limiter.limit("5 per hour")
def batch_analyze():
    """Start batch analysis of multiple images"""
    try:
        data = request.get_json()
        file_paths = data.get('file_paths', [])
        options = data.get('options', {})

        if not file_paths:
            return jsonify({'error': 'No files provided'}), 400

        # Create batch job
        batch_id = str(uuid.uuid4())
        batch_job = batch_processor.create_batch(batch_id, file_paths, options)

        # Start batch processing in background
        socketio.start_background_task(run_batch_analysis, batch_id)

        return jsonify({
            'success': True,
            'batch_id': batch_id,
            'total_files': len(file_paths),
            'message': 'Batch analysis started'
        }), 202

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# DASHBOARD ENDPOINTS
# ============================================================================

@dashboard_bp.route('/stats', methods=['GET'])
def get_dashboard_stats():
    """Get dashboard statistics"""
    try:
        stats = {
            'total_analyses': job_manager.get_total_analyses(),
            'recent_analyses': job_manager.get_recent_analyses(limit=10),
            'threat_distribution': job_manager.get_threat_distribution(),
            'detection_stats': job_manager.get_detection_stats(),
            'system_health': get_system_health()
        }

        return jsonify(stats), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@dashboard_bp.route('/timeline', methods=['GET'])
def get_analysis_timeline():
    """Get timeline of analyses"""
    try:
        days = request.args.get('days', default=7, type=int)
        timeline = job_manager.get_timeline(days=days)

        return jsonify(timeline), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@dashboard_bp.route('/threats/active', methods=['GET'])
def get_active_threats():
    """Get currently active threats"""
    try:
        threats = job_manager.get_active_threats()

        return jsonify(threats), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# JOBS ENDPOINTS
# ============================================================================

@jobs_bp.route('/list', methods=['GET'])
def list_jobs():
    """List all jobs"""
    try:
        status_filter = request.args.get('status')
        limit = request.args.get('limit', default=50, type=int)

        jobs = job_manager.list_jobs(status=status_filter, limit=limit)

        return jsonify(jobs), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@jobs_bp.route('/<job_id>/cancel', methods=['POST'])
def cancel_job(job_id):
    """Cancel a running job"""
    try:
        success = job_manager.cancel_job(job_id)

        if not success:
            return jsonify({'error': 'Job not found or cannot be cancelled'}), 400

        return jsonify({'success': True, 'message': 'Job cancelled'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@jobs_bp.route('/<job_id>/delete', methods=['DELETE'])
def delete_job(job_id):
    """Delete a job"""
    try:
        success = job_manager.delete_job(job_id)

        if not success:
            return jsonify({'error': 'Job not found'}), 404

        return jsonify({'success': True, 'message': 'Job deleted'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# REPORTS ENDPOINTS
# ============================================================================

@reports_bp.route('/generate', methods=['POST'])
def generate_report():
    """Generate report from analysis results"""
    try:
        data = request.get_json()
        job_id = data.get('job_id')
        report_format = data.get('format', 'pdf')  # pdf, json, html

        job = job_manager.get_job(job_id)
        if not job or job['status'] != 'completed':
            return jsonify({'error': 'Job not found or not completed'}), 400

        # Generate report
        report_path = analyzer.generate_report(
            job.get('results', {}),
            format=report_format
        )

        return jsonify({
            'success': True,
            'report_path': str(report_path),
            'format': report_format
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@reports_bp.route('/download/<filename>', methods=['GET'])
def download_report(filename):
    """Download generated report"""
    try:
        report_path = Path(request.app.config['REPORTS_FOLDER']) / filename

        if not report_path.exists():
            return jsonify({'error': 'Report not found'}), 404

        return send_file(report_path, as_attachment=True)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# SYSTEM ENDPOINTS
# ============================================================================

@system_bp.route('/health', methods=['GET'])
def health_check():
    """System health check"""
    try:
        health = get_system_health()
        return jsonify(health), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@system_bp.route('/metrics', methods=['GET'])
def get_metrics():
    """Get system metrics"""
    try:
        import psutil

        metrics = {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_usage': psutil.disk_usage('/').percent,
            'active_jobs': job_manager.get_active_count(),
            'queued_jobs': job_manager.get_queued_count()
        }

        return jsonify(metrics), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@system_bp.route('/e2ee/generate-keypair', methods=['POST'])
def generate_e2ee_keypair():
    """Generate E2EE keypair for specified curve"""
    try:
        from core.e2ee_protocol_handler import generate_e2ee_keypair as gen_keypair

        data = request.get_json()
        curve = data.get('curve', 'secp256r1')

        # Validate curve
        valid_curves = ['secp256r1', 'secp384r1', 'secp521r1', 'x25519']
        if curve not in valid_curves:
            return jsonify({
                'success': False,
                'error': f'Invalid curve. Must be one of: {", ".join(valid_curves)}'
            }), 400

        # Generate keypair
        private_key, public_key = gen_keypair(curve)

        return jsonify({
            'success': True,
            'curve': curve,
            'private_key': private_key.hex(),
            'public_key': public_key.hex(),
            'note': 'Store private key securely - it cannot be recovered'
        }), 200

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# ============================================================================
# WEBSOCKET EVENTS
# ============================================================================

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print('Client connected')


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print('Client disconnected')


@socketio.on('subscribe_job')
def handle_subscribe_job(data):
    """Subscribe to job updates"""
    job_id = data.get('job_id')
    # Join room for job-specific updates
    from flask_socketio import join_room
    join_room(f'job_{job_id}')


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def run_analysis(job_id, file_path, options):
    """Run analysis in background"""
    try:
        # Update job status
        job_manager.update_job_status(job_id, 'running')

        # Emit progress update
        socketio.emit('job_update', {
            'job_id': job_id,
            'status': 'running',
            'progress': 0
        }, room=f'job_{job_id}')

        # Run analysis
        async def analyze():
            results = await analyzer.analyze_image(
                file_path,
                progress_callback=lambda p: emit_progress(job_id, p)
            )
            return results

        # Run in event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(analyze())
        loop.close()

        # Update job with results
        job_manager.update_job(job_id, {
            'status': 'completed',
            'results': results,
            'completed_at': datetime.now().isoformat()
        })

        # Emit completion
        socketio.emit('job_update', {
            'job_id': job_id,
            'status': 'completed',
            'progress': 100,
            'results': results
        }, room=f'job_{job_id}')

    except Exception as e:
        job_manager.update_job(job_id, {
            'status': 'failed',
            'error': str(e),
            'failed_at': datetime.now().isoformat()
        })

        socketio.emit('job_update', {
            'job_id': job_id,
            'status': 'failed',
            'error': str(e)
        }, room=f'job_{job_id}')


def run_batch_analysis(batch_id):
    """Run batch analysis in background"""
    try:
        batch_processor.process_batch(
            batch_id,
            progress_callback=lambda p: emit_batch_progress(batch_id, p)
        )
    except Exception as e:
        print(f"Batch analysis error: {e}")


def emit_progress(job_id, progress):
    """Emit progress update for job"""
    socketio.emit('job_progress', {
        'job_id': job_id,
        'progress': progress
    }, room=f'job_{job_id}')


def emit_batch_progress(batch_id, progress):
    """Emit progress update for batch job"""
    socketio.emit('batch_progress', {
        'batch_id': batch_id,
        'progress': progress
    }, room=f'batch_{batch_id}')


def get_system_health():
    """Get system health information"""
    import psutil

    return {
        'status': 'healthy',
        'cpu_percent': psutil.cpu_percent(interval=1),
        'memory_percent': psutil.virtual_memory().percent,
        'disk_percent': psutil.disk_usage('/').percent,
        'timestamp': datetime.now().isoformat()
    }


def register_routes(app):
    """Register all routes (deprecated, kept for compatibility)"""
    pass
