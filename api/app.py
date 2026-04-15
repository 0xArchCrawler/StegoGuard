"""
StegoGuard API Application
Flask application with advanced features
"""

from flask import Flask
from flask_cors import CORS
from flask_socketio import SocketIO
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
from pathlib import Path

# Initialize extensions
socketio = SocketIO(cors_allowed_origins="*", async_mode='threading')
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)


def create_app(config=None):
    """Create and configure Flask application"""

    app = Flask(__name__)

    # Configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'stegoguard-premium-secret-key-change-in-production')
    app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size
    app.config['UPLOAD_FOLDER'] = Path(__file__).parent.parent.parent / 'uploads'
    app.config['REPORTS_FOLDER'] = Path(__file__).parent.parent.parent / 'reports'
    app.config['JOBS_FOLDER'] = Path(__file__).parent.parent.parent / 'jobs'

    # Create necessary directories
    app.config['UPLOAD_FOLDER'].mkdir(exist_ok=True)
    app.config['REPORTS_FOLDER'].mkdir(exist_ok=True)
    app.config['JOBS_FOLDER'].mkdir(exist_ok=True)

    # Apply custom config
    if config:
        app.config.update(config)

    # Initialize extensions
    CORS(app)
    socketio.init_app(app)
    limiter.init_app(app)

    # Register blueprints
    from .routes import analysis_bp, dashboard_bp, jobs_bp, reports_bp, system_bp
    app.register_blueprint(analysis_bp, url_prefix='/api/analysis')
    app.register_blueprint(dashboard_bp, url_prefix='/api/dashboard')
    app.register_blueprint(jobs_bp, url_prefix='/api/jobs')
    app.register_blueprint(reports_bp, url_prefix='/api/reports')
    app.register_blueprint(system_bp, url_prefix='/api/system')

    # Setup middleware
    from .middleware import setup_middleware
    setup_middleware(app)

    return app
