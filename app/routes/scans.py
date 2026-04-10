import hashlib
from pathlib import Path

from flask import Blueprint, g, jsonify, request

from app.config import Config
from app.database import SessionLocal
from app.middleware.auth import login_required, roles_required
from app.models.audit_log import AuditLog
from app.models.finding import Finding
from app.models.scan import Scan, ScanStatus, ScanType
from app.models.uploaded_apk import UploadedApk
from app.models.user import UserRole
from app.services.scan_manager import get_queue_size, submit_scan

scans_bp = Blueprint('scans', __name__)


def _log(db, user_id, action: str, details: str = None):
    db.add(AuditLog(
        user_id=user_id,
        action=action,
        details=details,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', '')[:256],
    ))


def _allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS


@scans_bp.route('/upload', methods=['POST'])
@login_required
@roles_required(UserRole.ADMIN, UserRole.SPECIALIST)
def upload_apk():
    if 'file' not in request.files:
        return jsonify({'error': 'No file field in request'}), 400
    file = request.files['file']
    if not file.filename:
        return jsonify({'error': 'Empty filename'}), 400
    if not _allowed_file(file.filename):
        return jsonify({'error': 'Only .apk files are allowed'}), 400

    original_name = Path(file.filename).name
    safe_name = ''.join(c for c in original_name if c.isalnum() or c in '._-')
    if not safe_name.lower().endswith('.apk'):
        safe_name += '.apk'

    content = file.read()
    sha256 = hashlib.sha256(content).hexdigest()
    unique_name = f'{sha256[:16]}_{safe_name}'
    save_path = Path(Config.UPLOAD_FOLDER) / unique_name
    save_path.parent.mkdir(parents=True, exist_ok=True)
    save_path.write_bytes(content)

    db = SessionLocal()
    try:
        uploaded = UploadedApk(
            user_id=g.current_user.id,
            original_name=safe_name,
            stored_name=unique_name,
            file_path=str(save_path),
            sha256=sha256,
            size_bytes=len(content),
        )
        db.add(uploaded)
        db.flush()
        _log(db, g.current_user.id, 'scan.apk_uploaded', f'{{"filename": "{safe_name}", "size": {len(content)}, "hash": "{sha256}"}}')
        db.commit()
        db.refresh(uploaded)
    finally:
        db.close()

    return jsonify({
        'message': 'APK uploaded successfully',
        'upload': uploaded.to_dict(),
    }), 201


@scans_bp.route('', methods=['POST'])
@login_required
@roles_required(UserRole.ADMIN, UserRole.SPECIALIST)
def start_scan():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'JSON body required'}), 400

    upload_id = data.get('upload_id')
    scan_type = (data.get('scan_type') or 'sast').strip().lower()
    package_name = (data.get('package_name') or '').strip()
    device_id = (data.get('device_id') or '').strip() or None

    errors = {}
    if not upload_id:
        errors['upload_id'] = 'Required. Start scan only from a registered upload.'
    if scan_type not in [t.value for t in ScanType]:
        errors['scan_type'] = f'Must be one of: {[t.value for t in ScanType]}'
    if scan_type in ('dast', 'both') and not package_name:
        errors['package_name'] = 'Required for DAST scan'
    if errors:
        return jsonify({'error': 'Validation failed', 'details': errors}), 400

    db = SessionLocal()
    try:
        upload = db.query(UploadedApk).filter(UploadedApk.id == int(upload_id)).first()
        if not upload:
            return jsonify({'error': 'Uploaded APK not found'}), 404
        if g.current_user.role == UserRole.SPECIALIST and upload.user_id != g.current_user.id:
            return jsonify({'error': 'Access denied'}), 403
        if not Path(upload.file_path).exists():
            return jsonify({'error': 'Uploaded APK is missing on disk'}), 409

        scan = Scan(
            user_id=g.current_user.id,
            apk_name=upload.original_name,
            apk_path=upload.file_path,
            package_name=package_name or None,
            scan_type=ScanType(scan_type),
            status=ScanStatus.PENDING,
        )
        db.add(scan)
        db.flush()
        _log(db, g.current_user.id, 'scan.started', f'{{"scan_id": {scan.id}, "type": "{scan_type}", "apk": "{scan.apk_name}", "upload_id": {upload.id}}}')
        db.commit()
        scan_id = scan.id
    finally:
        db.close()

    submit_scan(scan_id=scan_id, scan_type=scan_type, device_id=device_id)
    return jsonify({'message': 'Scan queued', 'scan_id': scan_id, 'status': 'pending', 'queue_position': get_queue_size()}), 202


@scans_bp.route('', methods=['GET'])
@login_required
def list_scans():
    db = SessionLocal()
    try:
        query = db.query(Scan)
        if g.current_user.role == UserRole.SPECIALIST:
            query = query.filter(Scan.user_id == g.current_user.id)
        status = request.args.get('status')
        if status:
            try:
                query = query.filter(Scan.status == ScanStatus(status))
            except ValueError:
                pass
        scan_type = request.args.get('type')
        if scan_type:
            try:
                query = query.filter(Scan.scan_type == ScanType(scan_type))
            except ValueError:
                pass
        page = max(1, int(request.args.get('page', 1)))
        limit = min(100, max(1, int(request.args.get('limit', 20))))
        total = query.count()
        scans = query.order_by(Scan.created_at.desc()).offset((page - 1) * limit).limit(limit).all()
        return jsonify({'scans': [s.to_dict() for s in scans], 'total': total, 'page': page, 'limit': limit, 'pages': (total + limit - 1) // limit}), 200
    finally:
        db.close()


@scans_bp.route('/uploads', methods=['GET'])
@login_required
@roles_required(UserRole.ADMIN, UserRole.SPECIALIST)
def list_uploads():
    db = SessionLocal()
    try:
        query = db.query(UploadedApk)
        if g.current_user.role == UserRole.SPECIALIST:
            query = query.filter(UploadedApk.user_id == g.current_user.id)
        uploads = query.order_by(UploadedApk.created_at.desc()).limit(30).all()
        return jsonify({'uploads': [u.to_dict() for u in uploads]}), 200
    finally:
        db.close()


@scans_bp.route('/<int:scan_id>', methods=['GET'])
@login_required
def get_scan(scan_id: int):
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        if g.current_user.role == UserRole.SPECIALIST and scan.user_id != g.current_user.id:
            return jsonify({'error': 'Access denied'}), 403
        return jsonify({'scan': scan.to_dict()}), 200
    finally:
        db.close()


@scans_bp.route('/<int:scan_id>/findings', methods=['GET'])
@login_required
def get_findings(scan_id: int):
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        if g.current_user.role == UserRole.SPECIALIST and scan.user_id != g.current_user.id:
            return jsonify({'error': 'Access denied'}), 403
        query = db.query(Finding).filter(Finding.scan_id == scan_id)
        severity = request.args.get('severity')
        if severity:
            from app.models.finding import Severity as SeverityEnum
            try:
                query = query.filter(Finding.severity == SeverityEnum(severity))
            except ValueError:
                pass
        source = request.args.get('source')
        if source in ('sast', 'dast'):
            query = query.filter(Finding.scan_source == source)
        findings = query.order_by(Finding.cvss_score.desc()).all()
        from collections import Counter
        severity_stats = Counter(f.severity.value for f in findings)
        return jsonify({
            'scan_id': scan_id,
            'total': len(findings),
            'stats': {
                'critical': severity_stats.get('critical', 0),
                'high': severity_stats.get('high', 0),
                'medium': severity_stats.get('medium', 0),
                'low': severity_stats.get('low', 0),
                'info': severity_stats.get('info', 0),
            },
            'findings': [f.to_dict() for f in findings],
        }), 200
    finally:
        db.close()


@scans_bp.route('/<int:scan_id>', methods=['DELETE'])
@login_required
@roles_required(UserRole.ADMIN)
def delete_scan(scan_id: int):
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        if scan.status == ScanStatus.RUNNING:
            return jsonify({'error': 'Cannot delete a running scan'}), 409
        apk_name = scan.apk_name
        db.delete(scan)
        _log(db, g.current_user.id, 'scan.deleted', f'{{"scan_id": {scan_id}, "apk": "{apk_name}"}}')
        db.commit()
        return jsonify({'message': f'Scan {scan_id} deleted'}), 200
    finally:
        db.close()
