"""
Module 9: Real-Time File System Monitor [cite: 50, 82]
Uses Watchdog library for zero-latency detection of new files.
When a new file appears in TARGET_DIR, it is automatically:
  1. Hashed (SHA-256)
  2. Scanned via VirusTotal
  3. Logged to the database
  4. Alerted via Slack
"""

import os
import sys
import time
import hashlib
from datetime import datetime
from dotenv import load_dotenv
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from scanner import check_file_threat
from notification import send_slack_alert

load_dotenv()
TARGET_DIR = os.getenv("TARGET_DIR", "./logs")


def compute_sha256(filepath):
    """Compute SHA-256 hash of a file (digital fingerprint)."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        print(f"[!] Error hashing {filepath}: {e}")
        return None


def log_to_database(file_hash, threat_score, status):
    """Module 15: Audit Logging — write scan result to soc_audit.db [cite: 168]."""
    try:
        from app import app, db, ThreatLog
        with app.app_context():
            new_log = ThreatLog(
                file_hash=file_hash,
                threat_score=threat_score,
                status=status
            )
            db.session.add(new_log)
            db.session.commit()
            print(f"[+] Logged to DB: {file_hash[:16]}... | Score: {threat_score} | {status}")
    except Exception as e:
        print(f"[!] DB logging failed: {e}")


class ThreatHandler(FileSystemEventHandler):
    """Handles file creation events in the monitored directory."""

    def on_created(self, event):
        if event.is_directory:
            return

        filepath = event.src_path
        filename = os.path.basename(filepath)
        print(f"\n{'='*60}")
        print(f"[ALERT] New file detected: {filename}")
        print(f"[INFO]  Path: {filepath}")
        print(f"[INFO]  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        # Step 1: Compute digital fingerprint
        time.sleep(0.5)  # Brief wait for file write to complete
        file_hash = compute_sha256(filepath)
        if not file_hash:
            print("[!] Skipping — could not compute hash")
            return
        print(f"[INFO]  SHA-256: {file_hash}")

        # Step 2: Query VirusTotal
        print("[SCAN]  Querying VirusTotal...")
        threat_score, status = check_file_threat(file_hash)
        print(f"[RESULT] Score: {threat_score}/70 | Status: {status}")

        # Step 3: Send Slack Alert
        send_slack_alert(filename, file_hash, threat_score, status)

        # Step 4: Log to database
        log_to_database(file_hash, threat_score, status)

        print(f"{'='*60}\n")


def start_monitor():
    """Start the Watchdog file system observer."""
    # Create target directory if it doesn't exist
    os.makedirs(TARGET_DIR, exist_ok=True)

    print(f"""
╔══════════════════════════════════════════════════════════╗
║           ⚡ SOC BOT — FILE SYSTEM MONITOR ⚡           ║
╠══════════════════════════════════════════════════════════╣
║  Status: ACTIVE                                         ║
║  Watching: {TARGET_DIR:<45s} ║
║  Engine: Watchdog + VirusTotal API                      ║
║  Alerts: Slack Webhook                                  ║
╚══════════════════════════════════════════════════════════╝
    """)
    print("[*] Monitoring for new files... (Press Ctrl+C to stop)\n")

    event_handler = ThreatHandler()
    observer = Observer()
    observer.schedule(event_handler, TARGET_DIR, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down monitor...")
        observer.stop()

    observer.join()
    print("[*] Monitor stopped.")


if __name__ == "__main__":
    start_monitor()
