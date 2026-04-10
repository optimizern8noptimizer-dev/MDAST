from datetime import datetime
from flask import Blueprint, g, jsonify, request

from app.database import SessionLocal
from app.middleware.auth import login_required, roles_required
from app.models.audit_log import AuditLog
from app.models.user import User, UserRole
from app.services.auth_service import create_token, decode_token, hash_password, revoke_token, verify_password

auth_bp = Blueprint('auth', __name__)


def _log(db, user_id, action: str, details: str = None):
    entry = AuditLog(
        user_id=user_id,
        action=action,
        details=details,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', '')[:256],
    )
    db.add(entry)


@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'JSON body required'}), 400

    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    if not username or not password:
        return jsonify({'error': 'username and password required'}), 400

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user or not verify_password(password, user.password_hash):
            _log(db, None, 'user.login_failed', f'{{"username": "{username}"}}')
            db.commit()
            return jsonify({'error': 'Invalid username or password'}), 401
        if not user.is_active:
            return jsonify({'error': 'Account is deactivated. Contact administrator'}), 403
        user.last_login = datetime.utcnow()
        _log(db, user.id, 'user.login', f'{{"username": "{username}"}}')
        db.commit()
        token = create_token(user.id, user.username, user.role.value)
        return jsonify({'token': token, 'user': user.to_dict()}), 200
    finally:
        db.close()


@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    payload = g.current_token
    revoke_token(payload.get('jti'), payload.get('exp'))
    db = SessionLocal()
    try:
        _log(db, g.current_user.id, 'user.logout')
        db.commit()
    finally:
        db.close()
    return jsonify({'message': 'Logged out successfully'}), 200


@auth_bp.route('/me', methods=['GET'])
@login_required
def me():
    return jsonify({'user': g.current_user.to_dict()}), 200


@auth_bp.route('/users', methods=['POST'])
@login_required
@roles_required(UserRole.ADMIN)
def create_user():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'JSON body required'}), 400

    username = (data.get('username') or '').strip()
    email = (data.get('email') or '').strip()
    password = data.get('password') or ''
    role_str = (data.get('role') or 'specialist').strip()

    errors = {}
    if not username or len(username) < 3:
        errors['username'] = 'Minimum 3 characters'
    if not email or '@' not in email:
        errors['email'] = 'Valid email required'
    if len(password) < 12:
        errors['password'] = 'Minimum 12 characters'
    if role_str not in [r.value for r in UserRole]:
        errors['role'] = f'Must be one of: {[r.value for r in UserRole]}'
    if errors:
        return jsonify({'error': 'Validation failed', 'details': errors}), 400

    db = SessionLocal()
    try:
        if db.query(User).filter(User.username == username).first():
            return jsonify({'error': f"Username '{username}' already exists"}), 409
        if db.query(User).filter(User.email == email).first():
            return jsonify({'error': f"Email '{email}' already registered"}), 409
        new_user = User(
            username=username,
            email=email,
            password_hash=hash_password(password),
            role=UserRole(role_str),
            is_active=True,
        )
        db.add(new_user)
        db.flush()
        _log(db, g.current_user.id, 'user.created', f'{{"new_user": "{username}", "role": "{role_str}"}}')
        db.commit()
        return jsonify({'message': 'User created', 'user': new_user.to_dict()}), 201
    finally:
        db.close()


@auth_bp.route('/users', methods=['GET'])
@login_required
@roles_required(UserRole.ADMIN)
def list_users():
    db = SessionLocal()
    try:
        users = db.query(User).order_by(User.id).all()
        return jsonify({'users': [u.to_dict() for u in users]}), 200
    finally:
        db.close()


@auth_bp.route('/users/<int:user_id>/activate', methods=['PUT'])
@login_required
@roles_required(UserRole.ADMIN)
def toggle_activate(user_id: int):
    if user_id == g.current_user.id:
        return jsonify({'error': 'Cannot deactivate yourself'}), 400
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        data = request.get_json(silent=True) or {}
        user.is_active = bool(data.get('is_active', not user.is_active))
        action = 'user.activated' if user.is_active else 'user.deactivated'
        _log(db, g.current_user.id, action, f'{{"target_user": "{user.username}"}}')
        db.commit()
        return jsonify({'message': f"User {'activated' if user.is_active else 'deactivated'}", 'user': user.to_dict()}), 200
    finally:
        db.close()


@auth_bp.route('/users/<int:user_id>/role', methods=['PUT'])
@login_required
@roles_required(UserRole.ADMIN)
def change_role(user_id: int):
    if user_id == g.current_user.id:
        return jsonify({'error': 'Cannot change your own role'}), 400
    data = request.get_json(silent=True) or {}
    role_str = (data.get('role') or '').strip()
    if role_str not in [r.value for r in UserRole]:
        return jsonify({'error': f'Role must be one of: {[r.value for r in UserRole]}'}), 400
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        old_role = user.role.value
        user.role = UserRole(role_str)
        _log(db, g.current_user.id, 'user.role_changed', f'{{"target_user": "{user.username}", "from": "{old_role}", "to": "{role_str}"}}')
        db.commit()
        return jsonify({'message': 'Role updated', 'user': user.to_dict()}), 200
    finally:
        db.close()
