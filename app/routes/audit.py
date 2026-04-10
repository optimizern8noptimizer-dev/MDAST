from flask import Blueprint, request, jsonify, g
from app.database import SessionLocal
from app.models.audit_log import AuditLog
from app.models.scan import Scan, ScanStatus
from app.models.finding import Finding, Severity
from app.models.user import User, UserRole
from app.models.report import Report
from app.middleware.auth import login_required, roles_required

audit_bp = Blueprint("audit", __name__)


@audit_bp.route("", methods=["GET"])
@login_required
@roles_required(UserRole.ADMIN, UserRole.AUDITOR)
def list_audit():
    db = SessionLocal()
    try:
        query = db.query(AuditLog)
        action = request.args.get("action")
        if action:
            query = query.filter(AuditLog.action.contains(action))
        user_id = request.args.get("user_id")
        if user_id:
            try:
                query = query.filter(AuditLog.user_id == int(user_id))
            except ValueError:
                pass
        page  = max(1, int(request.args.get("page", 1)))
        limit = min(200, max(1, int(request.args.get("limit", 50))))
        total = query.count()
        logs  = query.order_by(AuditLog.timestamp.desc()) \
                     .offset((page-1)*limit).limit(limit).all()
        return jsonify({
            "logs":  [l.to_dict() for l in logs],
            "total": total, "page": page, "limit": limit,
        }), 200
    finally:
        db.close()


@audit_bp.route("/stats", methods=["GET"])
@login_required
def dashboard_stats():
    db = SessionLocal()
    try:
        total_scans     = db.query(Scan).count()
        completed_scans = db.query(Scan).filter(Scan.status == ScanStatus.COMPLETED).count()
        running_scans   = db.query(Scan).filter(Scan.status == ScanStatus.RUNNING).count()
        failed_scans    = db.query(Scan).filter(Scan.status == ScanStatus.FAILED).count()
        total_findings  = db.query(Finding).count()
        total_users     = db.query(User).count()
        total_reports   = db.query(Report).count()

        findings_by_sev = {}
        for sev in Severity:
            findings_by_sev[sev.value] = db.query(Finding).filter(Finding.severity == sev).count()

        recent_scans = db.query(Scan).order_by(Scan.created_at.desc()).limit(5).all()

        return jsonify({
            "scans": {
                "total":     total_scans,
                "completed": completed_scans,
                "running":   running_scans,
                "failed":    failed_scans,
                "pending":   max(0, total_scans - completed_scans - running_scans - failed_scans),
            },
            "findings": {
                "total":       total_findings,
                "by_severity": findings_by_sev,
            },
            "users":        total_users,
            "reports":      total_reports,
            "recent_scans": [s.to_dict() for s in recent_scans],
        }), 200
    finally:
        db.close()