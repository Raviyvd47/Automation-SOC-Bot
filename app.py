import os
import hashlib
from flask import Flask, render_template, url_for, request, redirect, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from datetime import datetime
from scanner import check_file_threat       # Module 11: VirusTotal Logic
from notification import send_slack_alert   # Module 14: Slack Notification

app = Flask(__name__, template_folder='TEMPLATES')

# Module 11: Database Structure (soc_audit.db) [cite: 298, 302]
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///soc_audit.db'
app.secret_key = 'secret_key_107'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB upload limit
db = SQLAlchemy(app)

# Upload folder for file scanning
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- MODELS ---

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(100))

# Table: threat_logs (Section 11.2) [cite: 303, 304]
class ThreatLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)         # alert_id [cite: 306]
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)  # timestamp [cite: 308]
    file_name = db.Column(db.String(200), default="manual_scan") # file name
    file_hash = db.Column(db.String(100), nullable=False) # file_hash [cite: 310]
    threat_score = db.Column(db.Integer)                   # threat_score [cite: 312]
    status = db.Column(db.String(50))                      # status [cite: 314]

with app.app_context():
    db.create_all()

# --- HELPER ---

def compute_sha256(filepath):
    """Compute SHA-256 digital fingerprint of a file."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

# --- AUTH MIDDLEWARE ---

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access the SOC Terminal', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# --- ROUTES ---

@app.route('/')
def index():
    return render_template('index.html') 

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['user_name'] = user.name
            flash('Access Granted. Welcome Agent.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid Credentials', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_pw = generate_password_hash(password)
        new_user = User(name=name, email=email, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration Successful', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

# Module 14: Dashboard (ChatOps Simulation) [cite: 164, 322]
@app.route('/dashboard')
@login_required
def dashboard():
    recent_alerts = ThreatLog.query.order_by(ThreatLog.timestamp.desc()).limit(10).all()
    total_scans = ThreatLog.query.count()
    threats_found = ThreatLog.query.filter_by(status='THREAT').count()
    clean_count = ThreatLog.query.filter_by(status='CLEAN').count()
    return render_template(
        'dashboard.html',
        alerts=recent_alerts,
        total=total_scans,
        threats=threats_found,
        clean=clean_count,
        user_name=session.get('user_name', 'Agent')
    )

# ===== SCAN ENDPOINTS (Core Pipeline) =====

@app.route('/scan', methods=['POST'])
@login_required
def scan_hash():
    """
    Module 11+13+14+15: Full scan pipeline.
    Receives a hash → queries VirusTotal → logs to DB → sends Slack alert.
    """
    hash_val = request.form.get('file_hash', '').strip()
    if not hash_val:
        flash('Please enter a file hash to scan', 'error')
        return redirect(url_for('dashboard'))

    # Step 1: Query VirusTotal (Module 11)
    score, status = check_file_threat(hash_val)

    # Step 2: Log to database (Module 15: Audit Logging) [cite: 168]
    new_log = ThreatLog(
        file_name="manual_hash_scan",
        file_hash=hash_val,
        threat_score=score,
        status=status
    )
    db.session.add(new_log)
    db.session.commit()

    # Step 3: Send Slack notification (Module 14) [cite: 164]
    send_slack_alert("Manual Hash Scan", hash_val, score, status)

    if status == "THREAT":
        flash(f'🔴 THREAT DETECTED — Score: {score}/70 — Alert sent to Slack!', 'error')
    elif status == "CLEAN":
        flash(f'🟢 File is CLEAN — Score: 0/70', 'success')
    else:
        flash(f'⚠️ Scan result: {status}', 'warning')

    return redirect(url_for('dashboard'))


@app.route('/upload', methods=['POST'])
@login_required
def upload_scan():
    """
    File Upload Scanner.
    Accepts a file → computes SHA-256 → scans → logs → alerts.
    """
    if 'scan_file' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('dashboard'))

    file = request.files['scan_file']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('dashboard'))

    # Save file temporarily
    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)

    # Step 1: Compute SHA-256 digital fingerprint
    file_hash = compute_sha256(filepath)

    # Step 2: Query VirusTotal
    score, status = check_file_threat(file_hash)

    # Step 3: Log to database
    new_log = ThreatLog(
        file_name=filename,
        file_hash=file_hash,
        threat_score=score,
        status=status
    )
    db.session.add(new_log)
    db.session.commit()

    # Step 4: Send Slack notification
    send_slack_alert(filename, file_hash, score, status)

    # Cleanup uploaded file
    try:
        os.remove(filepath)
    except OSError:
        pass

    if status == "THREAT":
        flash(f'🔴 THREAT in "{filename}" — Score: {score}/70 — Slack alerted!', 'error')
    elif status == "CLEAN":
        flash(f'🟢 "{filename}" is CLEAN — Score: 0/70', 'success')
    else:
        flash(f'⚠️ "{filename}" — Result: {status}', 'warning')

    return redirect(url_for('dashboard'))


# Legacy URL-based scan (kept for backward compatibility)
@app.route('/scan/<hash_val>')
@login_required
def manual_scan(hash_val):
    score, status = check_file_threat(hash_val)
    new_log = ThreatLog(file_hash=hash_val, threat_score=score, status=status)
    db.session.add(new_log)
    db.session.commit()
    send_slack_alert("URL Scan", hash_val, score, status)
    flash(f"Scan Complete: {hash_val[:10]}... | Score: {score} | {status}", "success")
    return redirect(url_for('dashboard'))

@app.route('/logs')
@login_required
def logs():
    all_logs = ThreatLog.query.order_by(ThreatLog.timestamp.desc()).all()
    return render_template('logs.html', logs=all_logs)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)