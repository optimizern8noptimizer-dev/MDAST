import logging
import shutil
import threading
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from queue import Empty, Queue

from app.config import Config
from app.database import SessionLocal
from app.models.finding import Finding, Severity
from app.models.scan import Scan, ScanStatus, ScanType

logger = logging.getLogger(__name__)

_task_queue: Queue = Queue()
_worker_thread: threading.Thread | None = None
_worker_lock = threading.Lock()
_runtime = {
    'worker_alive': False,
    'tasks_processed': 0,
    'last_error': None,
    'last_started_at': None,
}


def _severity_from_str(s: str) -> Severity:
    return {
        'critical': Severity.CRITICAL,
        'high': Severity.HIGH,
        'medium': Severity.MEDIUM,
        'low': Severity.LOW,
        'info': Severity.INFO,
    }.get((s or '').lower(), Severity.INFO)


def _worker_loop():
    logger.info('[ScanManager] Worker started')
    _runtime['worker_alive'] = True
    _runtime['last_started_at'] = datetime.now(timezone.utc).isoformat()
    while True:
        try:
            task = _task_queue.get(timeout=Config.QUEUE_POLL_SECONDS)
            if task is None:
                break
            _execute_scan(task['scan_id'], task['scan_type'], task['device_id'])
            _runtime['tasks_processed'] += 1
            _task_queue.task_done()
        except Empty:
            continue
        except Exception as exc:
            logger.error('[ScanManager] Worker error: %s', exc, exc_info=True)
            _runtime['last_error'] = str(exc)
    _runtime['worker_alive'] = False


def _ensure_worker():
    global _worker_thread
    with _worker_lock:
        if _worker_thread is None or not _worker_thread.is_alive():
            _worker_thread = threading.Thread(target=_worker_loop, name='ScanManagerWorker', daemon=True)
            _worker_thread.start()
            logger.info('[ScanManager] Worker thread started')


def submit_scan(scan_id: int, scan_type: str, device_id: str | None = None) -> bool:
    _ensure_worker()
    _task_queue.put({'scan_id': scan_id, 'scan_type': scan_type, 'device_id': device_id})
    logger.info('[ScanManager] Scan %s queued (type=%s)', scan_id, scan_type)
    return True


def _execute_scan(scan_id: int, scan_type: str, device_id: str | None):
    db = SessionLocal()
    work_dir = None
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.error('[ScanManager] Scan %s not found in DB', scan_id)
            return
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        db.commit()
        work_dir = Path(tempfile.mkdtemp(prefix=f'masp_scan_{scan_id}_'))
        findings = []
        if scan_type in (ScanType.SAST.value, ScanType.BOTH.value):
            findings.extend(_run_sast(scan_id=scan_id, apk_path=scan.apk_path, work_dir=str(work_dir / 'sast')))
        if scan_type in (ScanType.DAST.value, ScanType.BOTH.value):
            if not scan.package_name:
                logger.warning('[ScanManager] No package_name for DAST scan %s — skipping', scan_id)
            else:
                findings.extend(_run_dast(scan_id=scan_id, apk_path=scan.apk_path, package_name=scan.package_name, device_id=device_id))
        _save_findings(db, scan_id, findings)
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()
        logger.info('[ScanManager] Scan %s completed — %s findings in %ss', scan_id, len(findings), scan.duration_seconds or 0)
    except Exception as exc:
        logger.error('[ScanManager] Scan %s failed: %s', scan_id, exc, exc_info=True)
        _runtime['last_error'] = str(exc)
        db.rollback()
        db2 = SessionLocal()
        try:
            scan2 = db2.query(Scan).filter(Scan.id == scan_id).first()
            if scan2:
                scan2.status = ScanStatus.FAILED
                scan2.error_msg = str(exc)[:1000]
                scan2.completed_at = datetime.now(timezone.utc)
                db2.commit()
        finally:
            db2.close()
    finally:
        db.close()
        if work_dir and work_dir.exists():
            shutil.rmtree(work_dir, ignore_errors=True)


def _run_sast(scan_id: int, apk_path: str, work_dir: str) -> list:
    from app.sast.engine import SastEngine
    engine = SastEngine(apk_path=apk_path, work_dir=work_dir)
    findings = engine.run(progress_callback=lambda step, pct: logger.info('[SAST:%s] %s%% — %s', scan_id, pct, step))
    return [('sast', f) for f in findings]


def _run_dast(scan_id: int, apk_path: str, package_name: str, device_id: str | None) -> list:
    from app.dast.engine import DastEngine
    engine = DastEngine(apk_path=apk_path, package_name=package_name, device_id=device_id, timeout_seconds=Config.FRIDA_TIMEOUT_SECONDS)
    findings = engine.run(progress_callback=lambda step, pct: logger.info('[DAST:%s] %s%% — %s', scan_id, pct, step))
    return [('dast', f) for f in findings]


def _save_findings(db, scan_id: int, raw_findings: list):
    for source, f in raw_findings:
        db.add(Finding(
            scan_id=scan_id,
            title=f.title,
            description=f.description,
            severity=_severity_from_str(f.severity),
            scan_source=source,
            cvss_score=getattr(f, 'cvss_score', None),
            cvss_vector=getattr(f, 'cvss_vector', None) or '',
            cwe_id=getattr(f, 'cwe_id', None),
            owasp_mobile=getattr(f, 'owasp_mobile', None),
            masvs_id=getattr(f, 'masvs_id', None),
            pci_dss_req=getattr(f, 'pci_dss_req', None),
            file_path=getattr(f, 'file_path', None),
            line_number=getattr(f, 'line_number', None),
            code_snippet=getattr(f, 'code_snippet', None),
            frida_output=getattr(f, 'frida_output', None),
            network_capture=getattr(f, 'network_capture', None),
            recommendation=getattr(f, 'recommendation', ''),
            references=getattr(f, 'references', ''),
        ))
    db.commit()


def get_scan_status(scan_id: int) -> dict | None:
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        return scan.to_dict() if scan else None
    finally:
        db.close()


def get_queue_size() -> int:
    return _task_queue.qsize()


def get_runtime_stats() -> dict:
    return dict(_runtime)
