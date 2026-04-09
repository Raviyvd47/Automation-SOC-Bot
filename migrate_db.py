"""
migrate_db.py — Safe DB Migration Script
=========================================
Adds the 'scan_type' column to the existing threat_log table
without dropping any existing data.

Run once:
    python migrate_db.py
"""

import sqlite3
import os

DB_PATH = os.path.join("instance", "soc_audit.db")


def migrate():
    if not os.path.exists(DB_PATH):
        print(f"[!] Database not found at {DB_PATH}")
        print("[*] It will be created automatically when you run app.py for the first time.")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Check existing columns
    cursor.execute("PRAGMA table_info(threat_log)")
    existing_cols = [row[1] for row in cursor.fetchall()]
    print(f"[*] Existing columns in threat_log: {existing_cols}")

    if "scan_type" not in existing_cols:
        print("[*] Adding 'scan_type' column...")
        cursor.execute("ALTER TABLE threat_log ADD COLUMN scan_type VARCHAR(20) DEFAULT 'hash'")
        conn.commit()
        print("[+] Migration successful — 'scan_type' column added.")
    else:
        print("[+] Column 'scan_type' already exists. No migration needed.")

    conn.close()


if __name__ == "__main__":
    print("=" * 50)
    print("  SOC Bot — Database Migration")
    print("=" * 50)
    migrate()
    print("Done.")
