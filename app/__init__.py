import logging
from logging.handlers import RotatingFileHandler

from flask import Flask, jsonify, send_from_directory

from app.config import Config, config
from app.database import healthcheck, init_db
from app.services.auth_service import cleanup_revoked_tokens


def _setup_logging(app: Flask) -> None:
    Config.ensure_directories()
    log_path = Config.LOGS_FOLDER / 'masp.log'
    handler = RotatingFileHandler(log_path, maxBytes=2_000_000, backupCount=3, encoding='utf-8')
    formatter = logging.Formatter('%(asctime)s %(levelname)s [%(name)s] %(message)s')
    handler.setFormatter(formatter)
    handler.setLevel(logging.INFO)

    if not any(isinstance(h, RotatingFileHandler) for h in app.logger.handlers):
        app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)


def create_app(config_name: str = 'default') -> Flask:
    app = Flask(__name__, static_folder='static')
    app.config.from_object(config[config_name])
    app.config['MAX_CONTENT_LENGTH'] = Config.MAX_CONTENT_LENGTH

    Config.ensure_directories()
    init_db()
    cleanup_revoked_tokens()
    _setup_logging(app)

    from app.routes.auth import auth_bp
    from app.routes.scans import scans_bp
    from app.routes.reports import reports_bp
    from app.routes.audit import audit_bp

    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(scans_bp, url_prefix='/api/scans')
    app.register_blueprint(reports_bp, url_prefix='/api/reports')
    app.register_blueprint(audit_bp, url_prefix='/api/audit')

    @app.route('/api/health')
    def health():
        from app.services.scan_manager import get_queue_size, get_runtime_stats
        cfg_issues = Config.validate()
        db_info = healthcheck()
        return {
            'status': 'ok' if db_info['database'] == 'ok' and not cfg_issues else 'degraded',
            'service': Config.APP_NAME,
            'version': Config.VERSION,
            'queue_size': get_queue_size(),
            'runtime': get_runtime_stats(),
            'database': db_info,
            'config_issues': cfg_issues,
        }, 200

    @app.errorhandler(413)
    def too_large(_):
        return jsonify({'error': 'File too large', 'max_bytes': Config.MAX_CONTENT_LENGTH}), 413

    @app.errorhandler(500)
    def internal_error(_):
        return jsonify({'error': 'Internal server error'}), 500

    @app.route('/', defaults={'path': ''})
    @app.route('/<path:path>')
    def spa(path):
        if path.startswith('api/'):
            return {'error': 'Not found'}, 404
        return send_from_directory(app.static_folder, 'index.html')

    return app
