"""
StegoGuard API Middleware
Request/response processing and security headers
"""

from flask import request, jsonify
from datetime import datetime
import time


def setup_middleware(app):
    """Setup all middleware for the application"""

    @app.before_request
    def before_request():
        """Execute before each request"""
        request.start_time = time.time()

        # Log request
        app.logger.info(f"{request.method} {request.path} - {request.remote_addr}")

    @app.after_request
    def after_request(response):
        """Execute after each request"""

        # Add security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

        # Add CORS headers (if not already added by Flask-CORS)
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'

        # Add timing header
        if hasattr(request, 'start_time'):
            elapsed = time.time() - request.start_time
            response.headers['X-Response-Time'] = f"{elapsed:.3f}s"

        # Log response
        app.logger.info(f"{request.method} {request.path} - {response.status_code} - {response.headers.get('X-Response-Time', 'N/A')}")

        return response

    @app.errorhandler(404)
    def not_found(error):
        """Handle 404 errors"""
        return jsonify({'error': 'Endpoint not found'}), 404

    @app.errorhandler(500)
    def internal_error(error):
        """Handle 500 errors"""
        app.logger.error(f"Internal error: {error}")
        return jsonify({'error': 'Internal server error'}), 500

    @app.errorhandler(413)
    def request_entity_too_large(error):
        """Handle file too large errors"""
        return jsonify({'error': 'File too large. Maximum size is 100MB'}), 413
