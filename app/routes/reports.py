from flask import Blueprint, request, jsonify, g, send_file
from pathlib import Path

from app.database import SessionLocal
from app.models.report import Report, ReportFormat
from app.models.scan import Scan, ScanStatus
from app.models.audit_log import AuditLog
from app.models.user import UserRole
from app.middleware.auth import login_required, roles_required
from app.services.report_generator import generate_report

reports_bp = Blueprint("reports", __name__)


def _log(db, user_id, action, details=None):
    db.add(AuditLog(
        user_id=user_id, action=action, details=details,
        ip_address=request.remote_addr,
        user_agent=request.headers.get("User-Agent", "")[:256],
    ))


@reports_bp.route("", methods=["POST"])
@login_required
@roles_required(UserRole.ADMIN, UserRole.SPECIALIST)
def create_report():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON body required"}), 400

    scan_id = data.get("scan_id")
    fmt     = (data.get("format") or "pdf").strip().lower()

    if not scan_id:
        return jsonify({"error": "scan_id required"}), 400
    if fmt not in ("pdf", "docx"):
        return jsonify({"error": "format must be 'pdf' or 'docx'"}), 400

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return jsonify({"error": "Scan not found"}), 404
        if scan.status != ScanStatus.COMPLETED:
            return jsonify({"error": f"Scan is {scan.status.value}. Only completed scans can be reported."}), 409
        if g.current_user.role == UserRole.SPECIALIST and scan.user_id != g.current_user.id:
            return jsonify({"error": "Access denied"}), 403
    finally:
        db.close()

    try:
        report = generate_report(
            scan_id=scan_id,
            generated_by_user_id=g.current_user.id,
            fmt=fmt,
        )
    except Exception as e:
        return jsonify({"error": f"Report generation failed: {str(e)}"}), 500

    db = SessionLocal()
    try:
        _log(db, g.current_user.id, "report.generated",
             f'{{"report_id": {report.id}, "scan_id": {scan_id}, "format": "{fmt}"}}')
        db.commit()
    finally:
        db.close()

    return jsonify({"message": "Report generated", "report": report.to_dict()}), 201


@reports_bp.route("", methods=["GET"])
@login_required
def list_reports():
    db = SessionLocal()
    try:
        query = db.query(Report)
        if g.current_user.role == UserRole.SPECIALIST:
            query = query.filter(Report.generated_by == g.current_user.id)
        reports = query.order_by(Report.generated_at.desc()).limit(100).all()
        return jsonify({"reports": [r.to_dict() for r in reports]}), 200
    finally:
        db.close()


@reports_bp.route("/<int:report_id>/download", methods=["GET"])
@login_required
def download_report(report_id: int):
    db = SessionLocal()
    try:
        report = db.query(Report).filter(Report.id == report_id).first()
        if not report:
            return jsonify({"error": "Report not found"}), 404
        if (g.current_user.role == UserRole.SPECIALIST
                and report.generated_by != g.current_user.id):
            return jsonify({"error": "Access denied"}), 403

        file_path = Path(report.file_path)
        if not file_path.exists():
            return jsonify({"error": "Report file not found on disk"}), 404

        mime = "application/pdf" if report.format == ReportFormat.PDF \
               else "application/vnd.openxmlformats-officedocument.wordprocessingml.document"

        _log(db, g.current_user.id, "report.downloaded",
             f'{{"report_id": {report_id}}}')
        db.commit()

        return send_file(
            str(file_path), mimetype=mime,
            as_attachment=True, download_name=file_path.name,
        )
    finally:
        db.close()