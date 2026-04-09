"""
SOC Bot — Background Scanning Service
=======================================
A standalone background service running on port 6000 that:
  1. Accepts scan requests (hash, IP, URL) via JSON API
  2. Scans via VirusTotal asynchronously using a thread pool
  3. Sends Slack alerts for threats
  4. Logs all results to soc_audit.db

Endpoints:
  POST /scan/hash    — Scan a file hash
  POST /scan/ip      — Scan an IP address
  POST /scan/url     — Scan a URL
  POST /webhook      — Generic webhook (auto-detects type)
  GET  /status       — Health check + queue stats
  GET  /results/<id> — Get scan result by ID

Usage:
  python service.py
"""

import os
import re
import time
import uuid
import logging
import threading
from queue import Queue, Full
from datetime import datetime
from functools import wraps
from collections import deque

from flask import Flask, request, jsonify
from dotenv import load_dotenv

from scanner import check_file_threat, check_ip_threat, check_url_threat
from notification import send_slack_alert

# ─── Configuration ────────────────────────────────────────────────────────────

load_dotenv()

SERVICE_PORT = int(os.getenv("SERVICE_PORT", 6000))
API_KEY = os.getenv("SOC_API_KEY", "soc-bot-default-key-change-me")
MAX_QUEUE_SIZE = int(os.getenv("MAX_QUEUE_SIZE", 100))
WORKER_THREADS = int(os.getenv("WORKER_THREADS", 3))
VT_RATE_LIMIT = int(os.getenv("VT_RATE_LIMIT", 4))  # requests per minute

# ─── Logging Setup ────────────────────────────────────────────────────────────

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/service.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("SOCService")

# ─── Flask App ────────────────────────────────────────────────────────────────

service_app = Flask(__name__)
service_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///soc_audit.db'
service_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
service_app.secret_key = 'service_secret_key_107'

# ─── Rate Limiter ─────────────────────────────────────────────────────────────

class RateLimiter:
    """
    Token-bucket rate limiter for VirusTotal API.
    Enforces max N requests per 60-second window.
    """
    def __init__(self, max_requests=4, window_seconds=60):
        self.max_requests = max_requests
        self.window = window_seconds
        self.timestamps = deque()
        self.lock = threading.Lock()

    def acquire(self):
        """Block until a rate-limit slot is available."""
        while True:
            with self.lock:
                now = time.time()
                # Remove timestamps older than the window
                while self.timestamps and self.timestamps[0] < now - self.window:
                    self.timestamps.popleft()

                if len(self.timestamps) < self.max_requests:
                    self.timestamps.append(now)
                    return True

            # Wait before retrying
            time.sleep(2)


rate_limiter = RateLimiter(max_requests=VT_RATE_LIMIT)

# ─── Scan Queue & Results Store ───────────────────────────────────────────────

scan_queue = Queue(maxsize=MAX_QUEUE_SIZE)
scan_results = {}  # scan_id → result dict
results_lock = threading.Lock()

# Stats counters
stats = {
    "total_queued": 0,
    "total_completed": 0,
    "total_threats": 0,
    "total_clean": 0,
    "total_errors": 0,
    "started_at": datetime.utcnow().isoformat() + "Z"
}
stats_lock = threading.Lock()

# ─── Database Helper ──────────────────────────────────────────────────────────

def log_to_database(file_name, file_hash, threat_score, status, scan_type="hash"):
    """Write scan result to soc_audit.db using the main app's models."""
    try:
        from app import app, db, ThreatLog
        with app.app_context():
            new_log = ThreatLog(
                file_name=file_name,
                file_hash=file_hash,
                threat_score=threat_score,
                status=status,
                scan_type=scan_type
            )
            db.session.add(new_log)
            db.session.commit()
            logger.info(f"DB logged: {file_hash[:16]}... | Score: {threat_score} | {status} | Type: {scan_type}")
            return new_log.id
    except Exception as e:
        logger.error(f"DB logging failed: {e}")
        return None

# ─── Worker Thread ────────────────────────────────────────────────────────────

def scan_worker():
    """
    Background worker that pulls scan jobs from the queue,
    rate-limits VirusTotal calls, and processes the full pipeline.
    """
    while True:
        job = scan_queue.get()
        scan_id = job["scan_id"]
        scan_type = job["scan_type"]
        target = job["target"]

        logger.info(f"Processing scan {scan_id}: {scan_type} → {target[:40]}...")

        try:
            # Rate limit before calling VirusTotal
            rate_limiter.acquire()

            # Step 1: Scan via VirusTotal
            if scan_type == "hash":
                score, status = check_file_threat(target)
                display_name = f"Service Hash Scan"
            elif scan_type == "ip":
                score, status = check_ip_threat(target)
                display_name = f"Service IP Scan"
            elif scan_type == "url":
                score, status = check_url_threat(target)
                display_name = f"Service URL Scan"
            else:
                score, status = 0, "UNSUPPORTED_TYPE"
                display_name = "Unknown"

            # Step 2: Send Slack alert
            send_slack_alert(display_name, target, score, status)

            # Step 3: Log to database
            log_id = log_to_database(display_name, target, score, status, scan_type)

            # Step 4: Store result
            result = {
                "scan_id": scan_id,
                "scan_type": scan_type,
                "target": target,
                "threat_score": score,
                "status": status,
                "log_id": log_id,
                "completed_at": datetime.utcnow().isoformat() + "Z",
                "state": "completed"
            }

            with results_lock:
                scan_results[scan_id] = result

            with stats_lock:
                stats["total_completed"] += 1
                if status == "THREAT":
                    stats["total_threats"] += 1
                elif status == "CLEAN":
                    stats["total_clean"] += 1

            logger.info(f"Scan {scan_id} complete: {status} (score: {score})")

        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}")
            with results_lock:
                scan_results[scan_id] = {
                    "scan_id": scan_id,
                    "scan_type": scan_type,
                    "target": target,
                    "status": "ERROR",
                    "error": str(e),
                    "completed_at": datetime.utcnow().isoformat() + "Z",
                    "state": "failed"
                }
            with stats_lock:
                stats["total_errors"] += 1

        finally:
            scan_queue.task_done()

# ─── Auth Middleware ──────────────────────────────────────────────────────────

def require_api_key(f):
    """Validates X-API-KEY header."""
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-KEY", "")
        if not key or key != API_KEY:
            return jsonify({
                "success": False,
                "error": "Unauthorized — invalid or missing API key",
                "hint": "Set X-API-KEY header with the value from your .env file"
            }), 401
        return f(*args, **kwargs)
    return decorated

# ─── Helper: Queue a Scan ────────────────────────────────────────────────────

def queue_scan(scan_type, target):
    """Create a scan job, add to queue, return scan_id."""
    scan_id = str(uuid.uuid4())[:8]

    job = {
        "scan_id": scan_id,
        "scan_type": scan_type,
        "target": target,
        "queued_at": datetime.utcnow().isoformat() + "Z"
    }

    try:
        scan_queue.put_nowait(job)
    except Full:
        return None, "Queue is full — try again later"

    # Store initial status
    with results_lock:
        scan_results[scan_id] = {
            "scan_id": scan_id,
            "scan_type": scan_type,
            "target": target,
            "state": "queued",
            "queued_at": job["queued_at"]
        }

    with stats_lock:
        stats["total_queued"] += 1

    return scan_id, None

# ═══════════════════════════════════════════════════════════════════════════════
#  API ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

# ─── Health / Status ──────────────────────────────────────────────────────────

@service_app.route("/status", methods=["GET"])
def status():
    """Health check + queue/scan statistics. No auth required."""
    return jsonify({
        "success": True,
        "service": "SOC Bot Background Scanner",
        "version": "1.0.0",
        "status": "operational",
        "port": SERVICE_PORT,
        "queue_size": scan_queue.qsize(),
        "queue_max": MAX_QUEUE_SIZE,
        "worker_threads": WORKER_THREADS,
        "rate_limit": f"{VT_RATE_LIMIT} req/min",
        "stats": stats,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }), 200

# ─── Scan Hash ────────────────────────────────────────────────────────────────

@service_app.route("/scan/hash", methods=["POST"])
@require_api_key
def scan_hash():
    """
    Scan a file hash via VirusTotal.
    Request: { "hash": "<md5|sha1|sha256>" }
    """
    data = request.get_json(silent=True) or {}
    file_hash = data.get("hash", "").strip()

    if not file_hash:
        return jsonify({"success": False, "error": "Missing required field: 'hash'"}), 400

    # Validate hex characters
    if not all(c in "0123456789abcdefABCDEF" for c in file_hash):
        return jsonify({"success": False, "error": "Invalid hash — must be hexadecimal"}), 400

    if len(file_hash) not in (32, 40, 64):
        return jsonify({"success": False, "error": "Invalid hash length — expected MD5(32), SHA-1(40), or SHA-256(64)"}), 400

    scan_id, error = queue_scan("hash", file_hash)
    if error:
        return jsonify({"success": False, "error": error}), 429

    return jsonify({
        "success": True,
        "message": "Scan queued successfully",
        "data": {
            "scan_id": scan_id,
            "scan_type": "hash",
            "target": file_hash,
            "state": "queued"
        }
    }), 202

# ─── Scan IP ──────────────────────────────────────────────────────────────────

@service_app.route("/scan/ip", methods=["POST"])
@require_api_key
def scan_ip():
    """
    Scan an IP address via VirusTotal.
    Request: { "ip": "1.2.3.4" }
    """
    data = request.get_json(silent=True) or {}
    ip_address = data.get("ip", "").strip()

    if not ip_address:
        return jsonify({"success": False, "error": "Missing required field: 'ip'"}), 400

    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if not ip_pattern.match(ip_address):
        return jsonify({"success": False, "error": "Invalid IP address format"}), 400

    scan_id, error = queue_scan("ip", ip_address)
    if error:
        return jsonify({"success": False, "error": error}), 429

    return jsonify({
        "success": True,
        "message": "IP scan queued successfully",
        "data": {
            "scan_id": scan_id,
            "scan_type": "ip",
            "target": ip_address,
            "state": "queued"
        }
    }), 202

# ─── Scan URL ─────────────────────────────────────────────────────────────────

@service_app.route("/scan/url", methods=["POST"])
@require_api_key
def scan_url():
    """
    Scan a URL via VirusTotal.
    Request: { "url": "https://example.com" }
    """
    data = request.get_json(silent=True) or {}
    target_url = data.get("url", "").strip()

    if not target_url:
        return jsonify({"success": False, "error": "Missing required field: 'url'"}), 400

    if not target_url.startswith(("http://", "https://")):
        return jsonify({"success": False, "error": "URL must start with http:// or https://"}), 400

    scan_id, error = queue_scan("url", target_url)
    if error:
        return jsonify({"success": False, "error": error}), 429

    return jsonify({
        "success": True,
        "message": "URL scan queued successfully",
        "data": {
            "scan_id": scan_id,
            "scan_type": "url",
            "target": target_url,
            "state": "queued"
        }
    }), 202

# ─── Generic Webhook ──────────────────────────────────────────────────────────

@service_app.route("/webhook", methods=["POST"])
@require_api_key
def webhook():
    """
    Generic webhook endpoint for external tools (SIEM, firewalls, etc.).
    Auto-detects scan type from the payload.

    Request (any of):
      { "hash": "abc123..." }
      { "ip": "1.2.3.4" }
      { "url": "https://..." }
    """
    data = request.get_json(silent=True) or {}

    if "hash" in data:
        scan_type = "hash"
        target = data["hash"].strip()
    elif "ip" in data:
        scan_type = "ip"
        target = data["ip"].strip()
    elif "url" in data:
        scan_type = "url"
        target = data["url"].strip()
    else:
        return jsonify({
            "success": False,
            "error": "Payload must include 'hash', 'ip', or 'url'"
        }), 400

    if not target:
        return jsonify({"success": False, "error": f"Empty value for '{scan_type}'"}), 400

    scan_id, error = queue_scan(scan_type, target)
    if error:
        return jsonify({"success": False, "error": error}), 429

    logger.info(f"Webhook received: {scan_type} → {target[:40]}")

    return jsonify({
        "success": True,
        "message": f"Webhook scan ({scan_type}) queued",
        "data": {
            "scan_id": scan_id,
            "scan_type": scan_type,
            "target": target,
            "state": "queued"
        }
    }), 202

# ─── Get Scan Result ──────────────────────────────────────────────────────────

@service_app.route("/results/<scan_id>", methods=["GET"])
@require_api_key
def get_result(scan_id):
    """Retrieve the result of a queued/completed scan by its scan_id."""
    with results_lock:
        result = scan_results.get(scan_id)

    if not result:
        return jsonify({"success": False, "error": f"Scan '{scan_id}' not found"}), 404

    return jsonify({"success": True, "data": result}), 200

# ═══════════════════════════════════════════════════════════════════════════════
#  START SERVICE
# ═══════════════════════════════════════════════════════════════════════════════

def start_service():
    """Start worker threads and the Flask service."""

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║        ⚡ SOC BOT — BACKGROUND SCANNING SERVICE ⚡         ║
╠══════════════════════════════════════════════════════════════╣
║  Port:        {str(SERVICE_PORT):<46s}║
║  Workers:     {str(WORKER_THREADS) + ' threads':<46s}║
║  Queue Max:   {str(MAX_QUEUE_SIZE) + ' jobs':<46s}║
║  Rate Limit:  {str(VT_RATE_LIMIT) + ' req/min (VirusTotal)':<46s}║
║  Auth:        API Key (X-API-KEY header)                    ║
╠══════════════════════════════════════════════════════════════╣
║  Endpoints:                                                 ║
║    POST /scan/hash    — Scan file hash                      ║
║    POST /scan/ip      — Scan IP address                     ║
║    POST /scan/url     — Scan URL                            ║
║    POST /webhook      — Generic webhook (auto-detect)       ║
║    GET  /status       — Health check & stats                ║
║    GET  /results/<id> — Get scan result                     ║
╚══════════════════════════════════════════════════════════════╝
    """)

    # Start worker threads
    for i in range(WORKER_THREADS):
        t = threading.Thread(target=scan_worker, daemon=True, name=f"ScanWorker-{i+1}")
        t.start()
        logger.info(f"Started worker thread: {t.name}")

    # Start Flask
    service_app.run(host="0.0.0.0", port=SERVICE_PORT, debug=False, threaded=True)


if __name__ == "__main__":
    start_service()
