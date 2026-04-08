"""
SOC Bot — REST API Endpoints (Blueprint)
=========================================
Provides JSON-based API endpoints for external integrations,
SIEM tools, and automation scripts to interact with the SOC Bot
without a browser session.

Authentication: API Key via X-API-KEY header (configured in .env)

Endpoints:
  POST /api/v1/scan/hash       — Scan a file hash via VirusTotal
  POST /api/v1/scan/file       — Upload & scan a file
  GET  /api/v1/logs            — Retrieve threat logs (paginated)
  GET  /api/v1/logs/<id>       — Get a single log entry by ID
  DELETE /api/v1/logs/<id>     — Delete a log entry by ID
  GET  /api/v1/stats           — Dashboard statistics
  GET  /api/v1/health          — Health check (no auth required)
"""

import os
import hashlib
from functools import wraps
from datetime import datetime

from flask import Blueprint, request, jsonify
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

from scanner import check_file_threat
from notification import send_slack_alert

load_dotenv()

# --- Blueprint ---
api_bp = Blueprint('api', __name__, url_prefix='/api/v1')

# --- API Key Auth ---
API_KEY = os.getenv("SOC_API_KEY", "soc-bot-default-key-change-me")

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def require_api_key(f):
    """Middleware: validates X-API-KEY header on every request."""
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get('X-API-KEY', '')
        if not key or key != API_KEY:
            return jsonify({
                "success": False,
                "error": "Unauthorized — invalid or missing API key",
                "hint": "Set X-API-KEY header with the value from your .env file"
            }), 401
        return f(*args, **kwargs)
    return decorated


def compute_sha256(filepath):
    """Compute SHA-256 digital fingerprint of a file."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


# =========================================================
#  HEALTH CHECK — No authentication required
# =========================================================

@api_bp.route('/health', methods=['GET'])
def health_check():
    """Returns service status. Useful for uptime monitors."""
    return jsonify({
        "success": True,
        "service": "SOC Bot API",
        "version": "1.0.0",
        "status": "operational",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }), 200


# =========================================================
#  SCAN BY HASH
# =========================================================

@api_bp.route('/scan/hash', methods=['POST'])
@require_api_key
def api_scan_hash():
    """
    Scan a file hash via VirusTotal.

    Request JSON:
        { "hash": "<sha256|md5|sha1>" }

    Response JSON:
        {
            "success": true,
            "data": {
                "file_hash": "...",
                "threat_score": 12,
                "status": "THREAT",
                "scanned_at": "..."
            }
        }
    """
    from app import db, ThreatLog

    data = request.get_json(silent=True) or {}
    file_hash = data.get('hash', '').strip()

    if not file_hash:
        return jsonify({
            "success": False,
            "error": "Missing required field: 'hash'"
        }), 400

    # Validate hash format (MD5=32, SHA1=40, SHA256=64 hex chars)
    if not all(c in '0123456789abcdefABCDEF' for c in file_hash):
        return jsonify({
            "success": False,
            "error": "Invalid hash — must be hexadecimal"
        }), 400

    if len(file_hash) not in (32, 40, 64):
        return jsonify({
            "success": False,
            "error": "Invalid hash length — expected MD5 (32), SHA-1 (40), or SHA-256 (64)"
        }), 400

    # Query VirusTotal
    score, status = check_file_threat(file_hash)

    # Log to database
    new_log = ThreatLog(
        file_name="api_hash_scan",
        file_hash=file_hash,
        threat_score=score,
        status=status
    )
    db.session.add(new_log)
    db.session.commit()

    # Send Slack notification
    send_slack_alert("API Hash Scan", file_hash, score, status)

    return jsonify({
        "success": True,
        "data": {
            "file_hash": file_hash,
            "threat_score": score,
            "status": status,
            "log_id": new_log.id,
            "scanned_at": new_log.timestamp.isoformat() + "Z"
        }
    }), 200


# =========================================================
#  SCAN BY FILE UPLOAD
# =========================================================

@api_bp.route('/scan/file', methods=['POST'])
@require_api_key
def api_scan_file():
    """
    Upload a file, compute its SHA-256, and scan via VirusTotal.

    Request: multipart/form-data with field 'file'

    Response JSON:
        {
            "success": true,
            "data": {
                "file_name": "...",
                "file_hash": "...",
                "threat_score": 0,
                "status": "CLEAN",
                "scanned_at": "..."
            }
        }
    """
    from app import db, ThreatLog

    if 'file' not in request.files:
        return jsonify({
            "success": False,
            "error": "No file provided — include a 'file' field in multipart form data"
        }), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({
            "success": False,
            "error": "Empty filename"
        }), 400

    # Save temporarily
    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)

    try:
        # Compute hash
        file_hash = compute_sha256(filepath)

        # Query VirusTotal
        score, status = check_file_threat(file_hash)

        # Log to database
        new_log = ThreatLog(
            file_name=filename,
            file_hash=file_hash,
            threat_score=score,
            status=status
        )
        db.session.add(new_log)
        db.session.commit()

        # Send Slack notification
        send_slack_alert(filename, file_hash, score, status)

        return jsonify({
            "success": True,
            "data": {
                "file_name": filename,
                "file_hash": file_hash,
                "threat_score": score,
                "status": status,
                "log_id": new_log.id,
                "scanned_at": new_log.timestamp.isoformat() + "Z"
            }
        }), 200

    finally:
        # Cleanup uploaded file
        try:
            os.remove(filepath)
        except OSError:
            pass


# =========================================================
#  THREAT LOGS — List / Get / Delete
# =========================================================

@api_bp.route('/logs', methods=['GET'])
@require_api_key
def api_get_logs():
    """
    Retrieve paginated threat logs.

    Query params:
        page (int, default=1)
        per_page (int, default=20, max=100)
        status (str, optional) — filter by status: THREAT, CLEAN, NOT_FOUND
    """
    from app import ThreatLog

    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)
    status_filter = request.args.get('status', '').strip().upper()

    query = ThreatLog.query.order_by(ThreatLog.timestamp.desc())

    if status_filter:
        query = query.filter_by(status=status_filter)

    paginated = query.paginate(page=page, per_page=per_page, error_out=False)

    logs = [{
        "id": log.id,
        "timestamp": log.timestamp.isoformat() + "Z",
        "file_name": log.file_name,
        "file_hash": log.file_hash,
        "threat_score": log.threat_score,
        "status": log.status
    } for log in paginated.items]

    return jsonify({
        "success": True,
        "data": logs,
        "pagination": {
            "page": paginated.page,
            "per_page": paginated.per_page,
            "total_items": paginated.total,
            "total_pages": paginated.pages,
            "has_next": paginated.has_next,
            "has_prev": paginated.has_prev
        }
    }), 200


@api_bp.route('/logs/<int:log_id>', methods=['GET'])
@require_api_key
def api_get_log(log_id):
    """Get a single threat log entry by ID."""
    from app import ThreatLog

    log = ThreatLog.query.get(log_id)
    if not log:
        return jsonify({
            "success": False,
            "error": f"Log entry #{log_id} not found"
        }), 404

    return jsonify({
        "success": True,
        "data": {
            "id": log.id,
            "timestamp": log.timestamp.isoformat() + "Z",
            "file_name": log.file_name,
            "file_hash": log.file_hash,
            "threat_score": log.threat_score,
            "status": log.status
        }
    }), 200


@api_bp.route('/logs/<int:log_id>', methods=['DELETE'])
@require_api_key
def api_delete_log(log_id):
    """Delete a threat log entry by ID."""
    from app import db, ThreatLog

    log = ThreatLog.query.get(log_id)
    if not log:
        return jsonify({
            "success": False,
            "error": f"Log entry #{log_id} not found"
        }), 404

    db.session.delete(log)
    db.session.commit()

    return jsonify({
        "success": True,
        "message": f"Log entry #{log_id} deleted"
    }), 200


# =========================================================
#  DASHBOARD STATS
# =========================================================

@api_bp.route('/stats', methods=['GET'])
@require_api_key
def api_stats():
    """Returns aggregate scan statistics for dashboard/reporting."""
    from app import ThreatLog

    total_scans = ThreatLog.query.count()
    threats_found = ThreatLog.query.filter_by(status='THREAT').count()
    clean_count = ThreatLog.query.filter_by(status='CLEAN').count()
    not_found = ThreatLog.query.filter_by(status='NOT_FOUND').count()

    # Latest 5 threats for quick overview
    recent_threats = ThreatLog.query.filter_by(status='THREAT') \
        .order_by(ThreatLog.timestamp.desc()).limit(5).all()

    return jsonify({
        "success": True,
        "data": {
            "total_scans": total_scans,
            "threats_found": threats_found,
            "clean_files": clean_count,
            "not_found": not_found,
            "threat_rate": round(
                (threats_found / total_scans * 100) if total_scans > 0 else 0, 2
            ),
            "recent_threats": [{
                "id": t.id,
                "file_name": t.file_name,
                "file_hash": t.file_hash,
                "threat_score": t.threat_score,
                "timestamp": t.timestamp.isoformat() + "Z"
            } for t in recent_threats]
        }
    }), 200
