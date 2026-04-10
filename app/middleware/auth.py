from functools import wraps

import jwt as pyjwt
from flask import g, jsonify, request

from app.database import SessionLocal
from app.models.user import User, UserRole
from app.services.auth_service import decode_token, is_token_revoked


def _extract_token() -> str | None:
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        return auth_header[7:]
    return None


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = _extract_token()
        if not token:
            return jsonify({'error': 'Authorization token required'}), 401
        try:
            payload = decode_token(token)
        except pyjwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired. Please login again'}), 401
        except pyjwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401

        if is_token_revoked(payload.get('jti', '')):
            return jsonify({'error': 'Session revoked. Please login again'}), 401

        db = SessionLocal()
        try:
            user = db.query(User).filter(User.id == int(payload['sub']), User.is_active.is_(True)).first()
            if not user:
                return jsonify({'error': 'User not found or deactivated'}), 401
            g.current_user = user
            g.current_token = payload
            return f(*args, **kwargs)
        finally:
            db.close()
    return decorated


def roles_required(*allowed_roles: UserRole):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user: User = getattr(g, 'current_user', None)
            if not user:
                return jsonify({'error': 'Authentication required'}), 401
            if user.role not in allowed_roles:
                return jsonify({
                    'error': 'Access denied',
                    'required_roles': [r.value for r in allowed_roles],
                    'your_role': user.role.value,
                }), 403
            return f(*args, **kwargs)
        return decorated
    return decorator
