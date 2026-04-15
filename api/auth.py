"""
StegoGuard Authentication & Authorization
JWT-based authentication with role-based access control
"""

from functools import wraps
from flask import request, jsonify, current_app
import jwt
from datetime import datetime, timedelta
import hashlib
import os


class AuthManager:
    """Manage authentication and authorization"""

    def __init__(self):
        self.secret_key = os.environ.get('JWT_SECRET', 'stegoguard-jwt-secret-change-in-production')
        self.algorithm = 'HS256'
        self.token_expiry = timedelta(hours=24)

    def generate_token(self, user_id, role='user'):
        """Generate JWT token for user"""
        payload = {
            'user_id': user_id,
            'role': role,
            'exp': datetime.utcnow() + self.token_expiry,
            'iat': datetime.utcnow()
        }

        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        return token

    def verify_token(self, token):
        """Verify JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    def hash_password(self, password):
        """Hash password using SHA256"""
        return hashlib.sha256(password.encode()).hexdigest()

    def verify_password(self, password, hashed):
        """Verify password against hash"""
        return self.hash_password(password) == hashed


# Global auth manager instance
auth_manager = AuthManager()


def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check for Authorization header
        auth_header = request.headers.get('Authorization')

        if not auth_header:
            return jsonify({'error': 'No authorization token provided'}), 401

        try:
            # Extract token
            token = auth_header.split(' ')[1] if ' ' in auth_header else auth_header

            # Verify token
            payload = auth_manager.verify_token(token)

            if not payload:
                return jsonify({'error': 'Invalid or expired token'}), 401

            # Attach user info to request
            request.user = payload

            return f(*args, **kwargs)

        except Exception as e:
            return jsonify({'error': 'Authentication failed'}), 401

    return decorated_function


def require_role(role):
    """Decorator to require specific role"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(request, 'user'):
                return jsonify({'error': 'Authentication required'}), 401

            if request.user.get('role') != role and request.user.get('role') != 'admin':
                return jsonify({'error': 'Insufficient permissions'}), 403

            return f(*args, **kwargs)

        return decorated_function
    return decorator


def get_current_user():
    """Get current authenticated user"""
    if hasattr(request, 'user'):
        return request.user
    return None
