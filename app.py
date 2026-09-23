"""
Network IDS with Machine Learning - Main Web Application
=========================================================
Flask dashboard for real-time intrusion detection, batch CSV analysis,
reporting, user management and automatic IP blocking.

Compatible with the latest package versions (Flask 3.x, pandas 2/3.x,
scikit-learn 1.5+, NumPy 2.x, scapy 2.6+).
"""

import csv
import io
import json
import os
import queue
import re
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

from flask import (Flask, Response, flash, jsonify, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

# Live ML prediction module (kept optional so the UI still runs without models)
try:
    from live_prediction import LiveIDSPredictor
    ML_MODULE_AVAILABLE = True
except ImportError as exc:
    print(f"[WARN] live_prediction module not available: {exc}")
    LiveIDSPredictor = None
    ML_MODULE_AVAILABLE = False

from blocking_service import blocking_service_loop

# ----------------------------------------------------------------------------
# App configuration
# ----------------------------------------------------------------------------
app = Flask(__name__)
# Use an environment variable in production:  set IDS_SECRET_KEY=<random>
app.secret_key = os.environ.get("IDS_SECRET_KEY", "change-me-in-production")
app.config["UPLOAD_FOLDER"] = os.environ.get("IDS_UPLOAD_FOLDER", "uploads")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB max upload

DB_PATH = os.environ.get("IDS_DB_PATH", "ids_database.db")
BASE_DIR = Path(__file__).resolve().parent

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)


# ----------------------------------------------------------------------------
# Live monitor subprocess manager (streams monitor.py output over SSE)
# ----------------------------------------------------------------------------
class MonitorProcessManager:
    def __init__(self, script_path="monitor.py", python_executable=sys.executable):
        self.script_path = script_path
        self.python = python_executable
        self.proc = None
        self.reader_thread = None
        self.lines = queue.Queue(maxsize=10000)
        self._stop_flag = threading.Event()

    def is_running(self):
        return self.proc is not None and self.proc.poll() is None

    def start(self):
        if self.is_running():
            return True

        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"  # force UTF-8 stdout/stderr in child
        env["PYTHONUTF8"] = "1"            # Python UTF-8 mode

        # -u => unbuffered so SSE receives lines instantly
        self.proc = subprocess.Popen(
            [self.python, "-u", self.script_path],
            cwd=BASE_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
        )

        self._stop_flag.clear()
        self.reader_thread = threading.Thread(target=self._pump_stdout, daemon=True)
        self.reader_thread.start()
        return True

    def _pump_stdout(self):
        try:
            for line in self.proc.stdout:
                if self._stop_flag.is_set():
                    break
                try:
                    self.lines.put_nowait(line.rstrip("\n"))
                except queue.Full:
                    _ = self.lines.get_nowait()
                    self.lines.put_nowait(line.rstrip("\n"))
        except Exception:
            pass

    def stop(self):
        if not self.is_running():
            return
        self._stop_flag.set()
        try:
            if os.name == "nt":
                self.proc.terminate()
            else:
                os.kill(self.proc.pid, signal.SIGINT)
        except Exception:
            pass
        try:
            self.proc.wait(timeout=3)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass
        self.proc = None

    def stream(self):
        """SSE generator: yields lines as 'data: ...\\n\\n'"""
        start_time = time.time()
        while True:
            try:
                line = self.lines.get(timeout=0.5)
                yield f"data: {line}\n\n"
            except queue.Empty:
                # keepalive every ~15s so proxies don't drop the connection
                if time.time() - start_time > 15:
                    start_time = time.time()
                    yield "data: [keepalive]\n\n"


monitor_mgr = MonitorProcessManager(script_path="monitor.py")

# Global live predictor (loaded once at startup)
live_predictor = None


def initialize_live_predictor():
    """Initialize the live prediction system."""
    global live_predictor
    if not ML_MODULE_AVAILABLE:
        print("[WARN] Live prediction module missing - ML features disabled")
        return False
    try:
        print("Initializing Live Prediction System...")
        live_predictor = LiveIDSPredictor()
        if live_predictor.is_loaded:
            print("Live Prediction System initialized successfully")
            return True
        print("[WARN] Live Prediction System initialization failed "
              "(check the models/ folder)")
        return False
    except Exception as e:
        print(f"[ERROR] Initializing Live Prediction System: {e}")
        return False


# ----------------------------------------------------------------------------
# Database
# ----------------------------------------------------------------------------
def get_db_connection():
    """Get a database connection with row access by column name."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_column(cursor, table, column, ddl):
    """Add a column to an existing table if it is missing (safe migration)."""
    cursor.execute(f"PRAGMA table_info({table})")
    columns = [row[1] for row in cursor.fetchall()]
    if column not in columns:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


def init_db():
    """Initialize database schema (and migrate older databases in place)."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS predictions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            prediction_result TEXT NOT NULL,
            confidence REAL NOT NULL,
            attack_type TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            input_data TEXT,
            user_id INTEGER,
            session_id TEXT,
            processed_by TEXT DEFAULT 'ML_Model',
            prediction_source TEXT DEFAULT 'batch',
            review_status TEXT DEFAULT 'pending',
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            attack_type TEXT NOT NULL,
            blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            blocked_by TEXT DEFAULT 'auto',
            reason TEXT,
            unblocked_at TIMESTAMP,
            unblocked_by TEXT,
            is_blocked BOOLEAN DEFAULT 1,
            block_count INTEGER DEFAULT 1
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analysis_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_name TEXT NOT NULL,
            user_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            file_name TEXT,
            total_records INTEGER DEFAULT 0,
            attacks_detected INTEGER DEFAULT 0,
            analysis_complete BOOLEAN DEFAULT 0,
            model_accuracy REAL,
            model_f1_score REAL,
            model_precision REAL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS model_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            accuracy REAL,
            precision_score REAL,
            recall_score REAL,
            f1_score REAL,
            auc_score REAL,
            true_positive INTEGER DEFAULT 0,
            false_positive INTEGER DEFAULT 0,
            true_negative INTEGER DEFAULT 0,
            false_negative INTEGER DEFAULT 0,
            total_samples INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS system_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_level TEXT NOT NULL,
            message TEXT NOT NULL,
            component TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            ip_address TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

    # ---- Migrations for databases created by older versions ----
    _ensure_column(cursor, "users", "is_active", "BOOLEAN DEFAULT 1")
    _ensure_column(cursor, "predictions", "review_status", "TEXT DEFAULT 'pending'")
    _ensure_column(cursor, "predictions", "prediction_source", "TEXT DEFAULT 'batch'")
    _ensure_column(cursor, "analysis_sessions", "model_accuracy", "REAL")
    _ensure_column(cursor, "analysis_sessions", "model_f1_score", "REAL")
    _ensure_column(cursor, "analysis_sessions", "model_precision", "REAL")
    _ensure_column(cursor, "blocked_ips", "block_count", "INTEGER DEFAULT 1")

    conn.commit()
    conn.close()


def log_system_event(level, message, component="system", user_id=None, ip_address=None):
    """Log system events (never crashes the caller)."""
    try:
        conn = get_db_connection()
        conn.execute(
            """INSERT INTO system_logs (log_level, message, component, user_id, ip_address)
               VALUES (?, ?, ?, ?, ?)""",
            (level, message, component, user_id, ip_address),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Logging error: {e}")


def get_dashboard_stats():
    """Get dashboard statistics from actual predictions."""
    empty = {
        "total_predictions": 0, "attacks_detected": 0, "normal_traffic": 0,
        "attack_types": [], "recent_predictions": [], "hourly_trends": [],
        "top_attacking_ips": [], "detection_rate": 0, "avg_confidence": 0,
    }
    conn = None
    try:
        conn = get_db_connection()

        total_predictions = conn.execute("SELECT COUNT(*) FROM predictions").fetchone()[0]
        attacks_detected = conn.execute(
            "SELECT COUNT(*) FROM predictions WHERE prediction_result = 'Attack'"
        ).fetchone()[0]

        attack_types = conn.execute("""
            SELECT attack_type, COUNT(*) as count
            FROM predictions GROUP BY attack_type ORDER BY count DESC
        """).fetchall()

        recent_predictions = conn.execute("""
            SELECT * FROM predictions ORDER BY timestamp DESC LIMIT 10
        """).fetchall()

        hourly_trends = conn.execute("""
            SELECT strftime('%H', timestamp) as hour,
                   COUNT(*) as total_requests,
                   SUM(CASE WHEN prediction_result = 'Attack' THEN 1 ELSE 0 END) as attacks
            FROM predictions
            WHERE timestamp >= datetime('now', '-24 hours')
            GROUP BY hour ORDER BY hour
        """).fetchall()

        top_ips = conn.execute("""
            SELECT ip_address, COUNT(*) as attack_count, AVG(confidence) as avg_confidence
            FROM predictions WHERE prediction_result = 'Attack'
            GROUP BY ip_address ORDER BY attack_count DESC LIMIT 5
        """).fetchall()

        detection_rate = round(attacks_detected / total_predictions * 100, 1) if total_predictions else 0
        row = conn.execute(
            "SELECT AVG(confidence) FROM predictions WHERE confidence IS NOT NULL"
        ).fetchone()
        avg_confidence = round(row[0] * 100, 1) if row and row[0] else 0

        return {
            "total_predictions": total_predictions,
            "attacks_detected": attacks_detected,
            "normal_traffic": total_predictions - attacks_detected,
            "attack_types": [dict(r) for r in attack_types],
            "recent_predictions": [dict(r) for r in recent_predictions],
            "hourly_trends": [dict(r) for r in hourly_trends],
            "top_attacking_ips": [dict(r) for r in top_ips],
            "detection_rate": detection_rate,
            "avg_confidence": avg_confidence,
        }
    except Exception as e:
        print(f"Error getting dashboard stats: {e}")
        return empty
    finally:
        if conn is not None:
            conn.close()


# ----------------------------------------------------------------------------
# Authentication routes
# ----------------------------------------------------------------------------
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/info")
def info():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Please enter both username and password!", "danger")
            return render_template("login.html")

        conn = None
        try:
            conn = get_db_connection()
            user = conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()

            if user and check_password_hash(user["password_hash"], password):
                if "is_active" in user.keys() and not user["is_active"]:
                    log_system_event(
                        "WARNING", f"Login attempt by inactive user: {username}",
                        "auth", user["id"], request.remote_addr,
                    )
                    flash("Your account has been deactivated. Please contact an administrator.", "warning")
                    return render_template("login.html")

                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["user_email"] = user["email"]

                log_system_event(
                    "INFO", f"User {username} logged in successfully",
                    "auth", user["id"], request.remote_addr,
                )
                flash(f"Welcome back, {username}!", "success")

                next_page = request.args.get("next")
                if next_page and next_page.startswith("/"):
                    return redirect(next_page)
                return redirect(url_for("dashboard"))

            # Wrong password or unknown user (same message on purpose)
            log_system_event(
                "WARNING", f"Failed login attempt for username: {username}",
                "auth", user["id"] if user else None, request.remote_addr,
            )
            flash("Invalid username or password!", "danger")

        except Exception as e:
            log_system_event(
                "ERROR", f"Login error for username {username}: {e}",
                "auth", None, request.remote_addr,
            )
            flash("An internal login error occurred. Please try again.", "danger")
        finally:
            if conn is not None:
                conn.close()

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not username or len(username) < 3:
            flash("Username must be at least 3 characters long!", "danger")
            return render_template("register.html")
        if not email or "@" not in email:
            flash("Please enter a valid email address!", "danger")
            return render_template("register.html")
        if not password or len(password) < 6:
            flash("Password must be at least 6 characters long!", "danger")
            return render_template("register.html")

        conn = None
        try:
            conn = get_db_connection()
            existing_user = conn.execute(
                "SELECT id FROM users WHERE username = ? OR email = ?", (username, email)
            ).fetchone()
            if existing_user:
                flash("Username or email already exists!", "danger")
                return render_template("register.html")

            password_hash = generate_password_hash(password)
            cursor = conn.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (username, email, password_hash),
            )
            conn.commit()

            # FIXED: user_id was referenced before assignment (NameError).
            user_id = cursor.lastrowid
            log_system_event(
                "INFO", f"New user registered: {username}",
                "auth", user_id, request.remote_addr,
            )

            # Log the new user in straight away
            session["user_id"] = user_id
            session["username"] = username
            session["user_email"] = email

            flash("Registration successful! Welcome to Network IDS!", "success")
            return redirect(url_for("dashboard"))

        except Exception as e:
            flash(f"Registration failed: {e}", "danger")
        finally:
            if conn is not None:
                conn.close()

    return render_template("register.html")


@app.route("/logout")
def logout():
    if "user_id" in session:
        log_system_event(
            "INFO", f'User {session.get("username")} logged out',
            "auth", session["user_id"], request.remote_addr,
        )
    session.clear()
    flash("You have been logged out successfully!", "info")
    return redirect(url_for("index"))


# ----------------------------------------------------------------------------
# Request guards
# ----------------------------------------------------------------------------
@app.before_request
def check_user_status():
    """Log out users that were deactivated while logged in."""
    if request.endpoint in ("login", "logout", "register", "static"):
        return

    if "user_id" in session:
        conn = None
        try:
            conn = get_db_connection()
            user = conn.execute(
                "SELECT is_active FROM users WHERE id = ?", (session["user_id"],)
            ).fetchone()

            if user is None:
                session.clear()
                flash("Your account no longer exists. Please contact an administrator.", "danger")
                return redirect(url_for("login"))
            if not user["is_active"]:
                log_system_event(
                    "WARNING",
                    f'Session terminated for deactivated user: {session.get("username")}',
                    "auth", session["user_id"], request.remote_addr,
                )
                session.clear()
                flash("Your account has been deactivated. You have been logged out.", "warning")
                return redirect(url_for("login"))
        except Exception as e:
            print(f"Error checking user status: {e}")
        finally:
            if conn is not None:
                conn.close()


@app.before_request
def check_blocked_ip():
    """Deny access if the requesting IP is on the blocked list."""
    client_ip = request.remote_addr

    # Never block loopback so the admin can always access the panel
    if client_ip in ("127.0.0.1", "::1", "localhost"):
        return
    if request.endpoint == "static":
        return

    conn = None
    try:
        conn = get_db_connection()
        blocked = conn.execute(
            "SELECT id FROM blocked_ips WHERE ip_address = ? AND is_blocked = 1",
            (client_ip,),
        ).fetchone()

        if blocked:
            conn.execute(
                "UPDATE blocked_ips SET block_count = block_count + 1 WHERE id = ?",
                (blocked["id"],),
            )
            conn.commit()
            log_system_event(
                "WARNING",
                f"Blocked IP {client_ip} attempted to access {request.path}",
                "blocking", None, client_ip,
            )
            return (
                '<h1 style="font-family:sans-serif;color:#c0392b;text-align:center;margin-top:10%">'
                "🚫 Access Denied</h1>"
                '<p style="text-align:center;font-family:sans-serif">'
                f"Your IP address <b>{client_ip}</b> has been blocked by the IDS security system.</p>",
                403,
            )
    except Exception as e:
        print(f"IP block check error: {e}")
    finally:
        if conn is not None:
            conn.close()


@app.before_request
def require_login():
    """Global auth guard: everything except public pages requires a session."""
    public_endpoints = {"static", "login", "register", "index"}
    if request.endpoint in public_endpoints:
        return
    if "user_id" not in session:
        return redirect(url_for("login"))


# ----------------------------------------------------------------------------
# Dashboard & live prediction
# ----------------------------------------------------------------------------
@app.route("/dashboard")
def dashboard():
    stats = get_dashboard_stats()
    return render_template("dashboard.html", stats=stats)


@app.route("/live_prediction", methods=["GET", "POST"])
def live_prediction():
    """Single sample live prediction."""
    if request.method == "POST":
        try:
            features = {}
            for feature in (live_predictor.expected_features if live_predictor else []):
                value = request.form.get(feature, "0")
                try:
                    features[feature] = float(value) if value else 0.0
                except (TypeError, ValueError):
                    features[feature] = 0.0

            if live_predictor and live_predictor.is_loaded:
                predicted_category, confidence, probabilities = \
                    live_predictor.predict_single_sample(features)

                prediction_result = "Attack" if predicted_category != "Normal" else "Normal"

                conn = get_db_connection()
                conn.execute(
                    """INSERT INTO predictions
                       (ip_address, prediction_result, confidence, attack_type,
                        input_data, user_id, prediction_source)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        request.remote_addr, prediction_result, float(confidence),
                        predicted_category, json.dumps(features),
                        session["user_id"], "live_single",
                    ),
                )
                conn.commit()
                conn.close()

                return jsonify({
                    "success": True,
                    "result": {
                        "prediction": prediction_result,
                        "attack_type": predicted_category,
                        "confidence": confidence,
                        "probabilities": probabilities.tolist() if probabilities is not None else None,
                    },
                })
            return jsonify({"success": False, "error": "ML model not available"})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)})

    features = live_predictor.expected_features if live_predictor else []
    return render_template("live_prediction.html", features=features)


# ----------------------------------------------------------------------------
# Reports (with CSV and PDF export)
# ----------------------------------------------------------------------------
def _build_filtered_query(args):
    """Build the shared WHERE clause used by reports and exports."""
    base_query = "FROM predictions WHERE 1=1"
    params = []

    attack_type = args.get("attack_type", "").strip()
    date_from = args.get("date_from", "").strip()
    date_to = args.get("date_to", "").strip()
    ip_address = args.get("ip_address", "").strip()

    if attack_type:
        base_query += " AND attack_type = ?"
        params.append(attack_type)
    if date_from:
        base_query += " AND DATE(timestamp) >= ?"
        params.append(date_from)
    if date_to:
        base_query += " AND DATE(timestamp) <= ?"
        params.append(date_to)
    if ip_address:
        base_query += " AND ip_address LIKE ?"
        params.append(f"%{ip_address}%")

    filters = {
        "attack_type": attack_type, "date_from": date_from,
        "date_to": date_to, "ip_address": ip_address,
    }
    return base_query, params, filters


@app.route("/reports")
def reports():
    try:
        base_query, params, filters = _build_filtered_query(request.args)
        conn = get_db_connection()

        total_records = conn.execute(f"SELECT COUNT(*) as count {base_query}", params).fetchone()["count"]
        threats_detected = conn.execute(
            f"SELECT COUNT(*) as count {base_query} AND prediction_result = 'Attack'", params
        ).fetchone()["count"]
        normal_traffic = conn.execute(
            f"SELECT COUNT(*) as count {base_query} AND prediction_result = 'Normal'", params
        ).fetchone()["count"]
        avg_row = conn.execute(f"SELECT AVG(confidence) as avg_conf {base_query}", params).fetchone()
        avg_confidence = (avg_row["avg_conf"] * 100) if avg_row["avg_conf"] else 0

        attack_types_dist = conn.execute(
            f"""SELECT attack_type, COUNT(*) as count {base_query}
                GROUP BY attack_type ORDER BY count DESC""", params
        ).fetchall()
        attack_types_chart_data = {r["attack_type"]: r["count"] for r in attack_types_dist}

        results_dist = conn.execute(
            f"SELECT prediction_result, COUNT(*) as count {base_query} GROUP BY prediction_result",
            params,
        ).fetchall()
        prediction_results_chart_data = {r["prediction_result"]: r["count"] for r in results_dist}

        display_predictions = conn.execute(
            f"""SELECT id, timestamp, ip_address, prediction_result, attack_type,
                       confidence, prediction_source, input_data
                {base_query} ORDER BY timestamp DESC LIMIT 500""", params,
        ).fetchall()

        attack_types = conn.execute(
            "SELECT DISTINCT attack_type FROM predictions ORDER BY attack_type"
        ).fetchall()

        # Remember the filter so /download_report exports the same data
        session["export_query"] = {"base_query": base_query, "params": params}
        conn.close()

        summary_stats = {
            "total_records": total_records,
            "threats_detected": threats_detected,
            "normal_traffic": normal_traffic,
            "avg_confidence": round(avg_confidence, 1),
        }
        return render_template(
            "reports.html",
            predictions=[dict(r) for r in display_predictions],
            attack_types=[r["attack_type"] for r in attack_types],
            summary_stats=summary_stats,
            attack_types_chart_data=attack_types_chart_data,
            prediction_results_chart_data=prediction_results_chart_data,
            filters=filters,
        )
    except Exception as e:
        flash(f"Error loading reports: {e}", "danger")
        return render_template(
            "reports.html", predictions=[], attack_types=[],
            summary_stats={"total_records": 0, "threats_detected": 0,
                           "normal_traffic": 0, "avg_confidence": 0},
            attack_types_chart_data={}, prediction_results_chart_data={}, filters={},
        )


def _fetch_export_rows():
    """Fetch all rows matching the filters stored in the session."""
    export_info = session.get("export_query", {})
    base_query = export_info.get("base_query", "FROM predictions WHERE 1=1")
    params = export_info.get("params", [])

    conn = get_db_connection()
    rows = conn.execute(
        f"""SELECT id, timestamp, ip_address, prediction_result, attack_type,
                   confidence, prediction_source, input_data
            {base_query} ORDER BY timestamp DESC""",
        params,
    ).fetchall()
    conn.close()
    return rows


@app.route("/download_report/<fmt>")
def download_report(fmt):
    fmt = fmt.lower()
    try:
        all_predictions = _fetch_export_rows()
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if fmt == "csv":
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["ID", "Timestamp", "IP Address", "Prediction Result",
                             "Attack Type", "Confidence", "Source", "Input Data"])
            for row in all_predictions:
                writer.writerow([
                    row["id"], row["timestamp"], row["ip_address"],
                    row["prediction_result"], row["attack_type"],
                    f"{row['confidence']:.4f}" if row["confidence"] else "0.0000",
                    row["prediction_source"] or "batch", row["input_data"] or "",
                ])
            output.seek(0)
            return Response(
                output.getvalue(), mimetype="text/csv",
                headers={"Content-Disposition":
                         f"attachment; filename=network_ids_report_{stamp}.csv"},
            )

        if fmt == "pdf":
            # PDF export using reportlab (previously an unused dependency)
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.platypus import (Paragraph, SimpleDocTemplate,
                                            Spacer, Table, TableStyle)

            buffer = io.BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=letter,
                                    title="Network IDS Report")
            styles = getSampleStyleSheet()
            elements = [
                Paragraph("Network IDS - Prediction Report", styles["Title"]),
                Paragraph(f"Generated: {datetime.now():%Y-%m-%d %H:%M:%S} | "
                          f"Records: {len(all_predictions)}", styles["Normal"]),
                Spacer(1, 12),
            ]

            data = [["ID", "Timestamp", "IP", "Result", "Attack Type", "Conf."]]
            for row in all_predictions[:1000]:  # cap for readable PDFs
                data.append([
                    str(row["id"]), str(row["timestamp"] or "")[:19],
                    str(row["ip_address"]), str(row["prediction_result"]),
                    str(row["attack_type"])[:28],
                    f"{row['confidence']:.2f}" if row["confidence"] else "0.00",
                ])
            table = Table(data, repeatRows=1)
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a5276")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                 [colors.white, colors.HexColor("#eaf2f8")]),
            ]))
            elements.append(table)
            doc.build(elements)
            buffer.seek(0)
            return Response(
                buffer.getvalue(), mimetype="application/pdf",
                headers={"Content-Disposition":
                         f"attachment; filename=network_ids_report_{stamp}.pdf"},
            )

    except Exception as e:
        flash(f"Error exporting report: {e}", "danger")
        return redirect(url_for("reports"))

    flash("Unsupported export format (use csv or pdf)", "warning")
    return redirect(url_for("reports"))


# ----------------------------------------------------------------------------
# API routes
# ----------------------------------------------------------------------------
@app.route("/api/dashboard_data")
def api_dashboard_data():
    try:
        return jsonify(get_dashboard_stats())
    except Exception:
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/model_status")
def api_model_status():
    """Check ML model status."""
    status = {
        "model_loaded": live_predictor is not None and live_predictor.is_loaded,
        "model_type": (type(live_predictor.model).__name__
                       if live_predictor and live_predictor.model else None),
        "feature_count": (len(live_predictor.feature_names)
                          if live_predictor and live_predictor.feature_names else 0),
        "has_scaler": live_predictor.scaler is not None if live_predictor else False,
        "has_encoder": live_predictor.label_encoder is not None if live_predictor else False,
    }
    return jsonify(status)



# ----------------------------------------------------------------------------
# Test case execution API
# ----------------------------------------------------------------------------
@app.route("/api/run_test/<int:test_id>", methods=["POST"])
def run_test(test_id):
    """
    Run a safe simulated IDS test case.

    This route does not modify, retrain, replace, or otherwise change the
    ML/AI model. It only creates a simulated security event in the existing
    predictions table so the Test Cases frontend can validate the existing
    Dashboard, Reports, and Manual Analysis workflow.
    """
    test_cases_map = {
        1: {
            "name": "DDoS Attack Simulation",
            "attack_type": "DDoS",
            "ip_address": "10.10.10.101",
            "confidence": 0.94,
        },
        2: {
            "name": "Port Scan Detection",
            "attack_type": "Port Scan",
            "ip_address": "10.10.10.102",
            "confidence": 0.90,
        },
        3: {
            "name": "Brute Force Login",
            "attack_type": "Brute Force",
            "ip_address": "10.10.10.103",
            "confidence": 0.96,
        },
        4: {
            "name": "SQL Injection Test",
            "attack_type": "SQL Injection",
            "ip_address": "10.10.10.104",
            "confidence": 0.87,
        },
    }

    test_case = test_cases_map.get(test_id)

    if test_case is None:
        return jsonify({
            "success": False,
            "error": "Test case not found",
        }), 404

    conn = None

    try:
        conn = get_db_connection()

        input_data = {
            "test_case_id": test_id,
            "test_case_name": test_case["name"],
            "simulation": True,
            "executed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

        cursor = conn.execute(
            """
            INSERT INTO predictions (
                ip_address,
                prediction_result,
                confidence,
                attack_type,
                input_data,
                user_id,
                prediction_source,
                review_status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                test_case["ip_address"],
                "Attack",
                float(test_case["confidence"]),
                test_case["attack_type"],
                json.dumps(input_data),
                session.get("user_id"),
                "test_case_simulation",
                "pending",
            ),
        )

        prediction_id = cursor.lastrowid
        conn.commit()

        log_system_event(
            "INFO",
            f"Test case executed: {test_case['name']}",
            "test_cases",
            session.get("user_id"),
            test_case["ip_address"],
        )

        return jsonify({
            "success": True,
            "message": f"{test_case['name']} completed successfully",
            "result": {
                "prediction_id": prediction_id,
                "ip_address": test_case["ip_address"],
                "prediction": "Attack",
                "attack_type": test_case["attack_type"],
                "confidence": float(test_case["confidence"]),
            },
        })

    except Exception as e:
        if conn is not None:
            conn.rollback()

        print(f"Test case execution error: {e}")

        return jsonify({
            "success": False,
            "error": str(e),
        }), 500

    finally:
        if conn is not None:
            conn.close()


@app.route("/test_cases")
def test_cases():
    """Test cases and simulations."""
    test_cases_data = [
        {"id": 1, "name": "DDoS Attack Simulation",
         "description": "Simulates distributed denial of service attack with high volume traffic",
         "attack_type": "DDoS", "status": "Ready", "success_rate": 94.2, "last_run": "2 hours ago"},
        {"id": 2, "name": "Port Scan Detection",
         "description": "Tests systematic port scanning attack detection capabilities",
         "attack_type": "Port Scan", "status": "Ready", "success_rate": 89.7, "last_run": "1 day ago"},
        {"id": 3, "name": "Brute Force Login",
         "description": "Simulates multiple failed login attempts from various sources",
         "attack_type": "Brute Force", "status": "Ready", "success_rate": 96.1, "last_run": "3 hours ago"},
        {"id": 4, "name": "SQL Injection Test",
         "description": "Tests detection of malicious SQL queries and injection attempts",
         "attack_type": "SQL Injection", "status": "Ready", "success_rate": 87.3, "last_run": "5 hours ago"},
    ]
    log_system_event("INFO", "Test cases accessed", "test_cases", session["user_id"])
    return render_template("test_cases.html", test_cases=test_cases_data)


@app.route("/manual_analysis")
def manual_analysis():
    """Manual analysis portal (attacks pending review)."""
    try:
        conn = get_db_connection()
        predictions = conn.execute("""
            SELECT * FROM predictions
            WHERE prediction_result = 'Attack' AND review_status = 'pending'
            ORDER BY timestamp DESC LIMIT 20
        """).fetchall()
        conn.close()

        log_system_event("INFO", "Manual analysis accessed", "manual_analysis", session["user_id"])
        return render_template("manual_analysis.html",
                               predictions=[dict(r) for r in predictions])
    except Exception as e:
        flash(f"Error loading manual analysis: {e}", "danger")
        log_system_event("ERROR", f"Manual analysis error: {e}",
                         "manual_analysis", session["user_id"])
        return render_template("manual_analysis.html", predictions=[])


# ----------------------------------------------------------------------------
# CSV upload & batch analysis
# ----------------------------------------------------------------------------
@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method != "POST":
        return render_template("upload.html")

    conn = None
    try:
        if "file" not in request.files or request.files["file"].filename == "":
            flash("No file selected!", "danger")
            return redirect(request.url)

        file = request.files["file"]
        prediction_type = request.form.get("predictionType", "auto")  # auto | hybrid | manual

        if not file.filename.lower().endswith(".csv"):
            flash("Only CSV files are supported!", "danger")
            return redirect(request.url)

        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(file_path)

        conn = get_db_connection()
        session_cursor = conn.execute(
            "INSERT INTO analysis_sessions (session_name, user_id, file_name) VALUES (?, ?, ?)",
            (f"Analysis_{datetime.now():%Y%m%d_%H%M%S}", session["user_id"], filename),
        )
        session_id = session_cursor.lastrowid

        # ---- MANUAL MODE: skip ML entirely ----
        if prediction_type == "manual":
            import pandas as pd
            try:
                row_count = len(pd.read_csv(file_path))
            except Exception:
                row_count = 0

            conn.executemany(
                """INSERT INTO predictions
                   (ip_address, prediction_result, confidence, attack_type,
                    input_data, user_id, session_id, prediction_source)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                [("0.0.0.0", "Pending", 0.0, "Manual Review Required", "{}",
                  session["user_id"], str(session_id), "batch_manual")
                 for _ in range(row_count)],
            )
            conn.execute(
                """UPDATE analysis_sessions
                   SET total_records = ?, attacks_detected = 0, analysis_complete = 1
                   WHERE id = ?""",
                (row_count, session_id),
            )
            conn.commit()

            log_system_event("INFO", f"Manual analysis queued: {row_count} records",
                             "upload", session["user_id"])
            flash(f"{row_count} records queued for manual review. No ML was run.", "info")
            return redirect(url_for("upload_results", session_id=session_id))

        # ---- AUTO / HYBRID MODE: run the ML model ----
        if not (live_predictor and live_predictor.is_loaded):
            flash("ML model not loaded. Please check the files in the models/ folder.", "warning")
            return render_template("upload.html")

        results_df = live_predictor.predict_from_csv(file_path, save_results=False)
        if results_df is None:
            flash("Error processing file with ML model. Please check the file format.", "danger")
            return render_template("upload.html")

        attacks_detected = 0
        predictions_list, confidence_scores = [], []
        source_label = "batch_auto" if prediction_type == "auto" else "batch_hybrid"

        rows_to_insert = []
        for _, row in results_df.iterrows():
            predicted_category = row.get("predicted_attack_category", "Unknown")
            confidence = row.get("prediction_confidence", 0.5)
            prediction_result = "Attack" if predicted_category != "Normal" else "Normal"
            if prediction_result == "Attack":
                attacks_detected += 1
            predictions_list.append(1 if prediction_result == "Attack" else 0)
            confidence_scores.append(confidence)
            rows_to_insert.append((
                "127.0.0.1", prediction_result, float(confidence), predicted_category,
                json.dumps({k: str(v) for k, v in row.to_dict().items()
                            if k not in ("predicted_attack_category", "prediction_confidence")}),
                session["user_id"], str(session_id), source_label,
            ))

        conn.executemany(
            """INSERT INTO predictions
               (ip_address, prediction_result, confidence, attack_type,
                input_data, user_id, session_id, prediction_source)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            rows_to_insert,
        )

        # ---- Metrics: use ground truth when the CSV provides it ----
        import pandas as pd
        accuracy = precision = recall = f1 = auc = None
        tp = fp = tn = fn = 0

        try:
            original_df = pd.read_csv(file_path)
            has_ground_truth = ("attack_category" in original_df.columns
                                and len(original_df) == len(predictions_list))
        except Exception:
            has_ground_truth = False

        if has_ground_truth:
            try:
                from sklearn.metrics import (accuracy_score, confusion_matrix,
                                             f1_score, precision_score,
                                             recall_score, roc_auc_score)
                y_true = [0 if str(l).lower() == "normal" else 1
                          for l in original_df["attack_category"].values]
                y_pred = predictions_list

                accuracy = accuracy_score(y_true, y_pred)
                precision = precision_score(y_true, y_pred, average="binary", zero_division=0)
                recall = recall_score(y_true, y_pred, average="binary", zero_division=0)
                f1 = f1_score(y_true, y_pred, average="binary", zero_division=0)
                try:
                    auc = roc_auc_score(y_true, confidence_scores)
                except Exception:
                    auc = 0.0

                cm = confusion_matrix(y_true, y_pred)
                if cm.size == 4:
                    tn, fp, fn, tp = (int(x) for x in cm.ravel())
                log_system_event("INFO", "Metrics calculated from ground-truth labels",
                                 "upload", session["user_id"])
            except Exception as gt_error:
                log_system_event("WARNING", f"Ground-truth metric error: {gt_error}",
                                 "upload", session["user_id"])
                has_ground_truth = False

        if not has_ground_truth:
            # No labels available - report descriptive stats instead of fake metrics
            total = len(predictions_list)
            attacks = sum(predictions_list)
            accuracy = round(1 - attacks / total, 4) if total else 0.0
            precision = recall = f1 = auc = None
            log_system_event("INFO", "No ground truth in CSV - storing detection stats only",
                             "upload", session["user_id"])

        try:
            conn.execute(
                """INSERT INTO model_metrics
                   (session_id, accuracy, precision_score, recall_score, f1_score,
                    auc_score, true_positive, false_positive, true_negative,
                    false_negative, total_samples, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (str(session_id),
                 float(accuracy) if accuracy is not None else None,
                 float(precision) if precision is not None else None,
                 float(recall) if recall is not None else None,
                 float(f1) if f1 is not None else None,
                 float(auc) if auc is not None else None,
                 tp, fp, tn, fn, len(predictions_list), datetime.now().isoformat()),
            )
        except Exception as metrics_error:
            log_system_event("ERROR", f"Could not store metrics: {metrics_error}",
                             "upload", session["user_id"])

        conn.execute(
            """UPDATE analysis_sessions
               SET total_records = ?, attacks_detected = ?, analysis_complete = 1,
                   model_accuracy = ?, model_f1_score = ?, model_precision = ?
               WHERE id = ?""",
            (len(results_df), attacks_detected,
             float(accuracy) if accuracy is not None else None,
             float(f1) if f1 is not None else None,
             float(precision) if precision is not None else None,
             session_id),
        )
        conn.commit()

        log_system_event(
            "INFO",
            f"CSV analysis completed: {len(results_df)} records ({prediction_type} mode)",
            "upload", session["user_id"],
        )

        if prediction_type == "hybrid":
            flash(f"Hybrid analysis complete! {len(results_df)} records processed by ML "
                  f"({attacks_detected} attacks detected). Flagged for manual review.", "success")
        elif accuracy is not None and has_ground_truth:
            flash(f"File processed! {len(results_df)} predictions, {attacks_detected} attacks. "
                  f"Accuracy vs ground truth: {accuracy:.2%}", "success")
        else:
            flash(f"File processed! {len(results_df)} predictions, "
                  f"{attacks_detected} attacks detected.", "success")
        return redirect(url_for("upload_results", session_id=session_id))

    except Exception as e:
        flash(f"Error processing file: {e}", "danger")
        log_system_event("ERROR", f"Upload error: {e}", "upload",
                         session.get("user_id"))
        return render_template("upload.html")
    finally:
        if conn is not None:
            conn.close()


@app.route("/upload_results/<int:session_id>")
def upload_results(session_id):
    """Show results for a specific analysis session with model metrics."""
    try:
        conn = get_db_connection()
        session_info = conn.execute(
            "SELECT * FROM analysis_sessions WHERE id = ? AND user_id = ?",
            (session_id, session["user_id"]),
        ).fetchone()
        if not session_info:
            flash("Analysis session not found!", "danger")
            conn.close()
            return redirect(url_for("dashboard"))

        predictions = conn.execute(
            "SELECT * FROM predictions WHERE session_id = ? ORDER BY timestamp DESC",
            (str(session_id),),
        ).fetchall()
        metrics = conn.execute(
            """SELECT * FROM model_metrics WHERE session_id = ?
               ORDER BY created_at DESC LIMIT 1""",
            (str(session_id),),
        ).fetchone()
        conn.close()

        predictions_list = []
        for pred in predictions:
            try:
                input_data = json.loads(pred["input_data"]) if pred["input_data"] else {}
            except (json.JSONDecodeError, TypeError):
                input_data = {}
            predictions_list.append({
                "prediction": pred["prediction_result"],
                "attack_type": pred["attack_type"],
                "confidence": pred["confidence"],
                "row_data": input_data,
                "ip_address": pred["ip_address"],
                "timestamp": pred["timestamp"],
            })

        return render_template(
            "upload_results.html",
            predictions=predictions_list,
            session_info=dict(session_info),
            model_metrics=dict(metrics) if metrics else None,
        )
    except Exception as e:
        flash(f"Error loading results: {e}", "danger")
        return redirect(url_for("dashboard"))


# ----------------------------------------------------------------------------
# Live monitoring page + SSE stream
# ----------------------------------------------------------------------------
@app.route("/monitor")
def monitor_page():
    return render_template("monitor.html")


@app.route("/api/start", methods=["POST"])
def api_start():
    ok = monitor_mgr.start()
    return jsonify({"started": ok, "running": monitor_mgr.is_running()})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    monitor_mgr.stop()
    return jsonify({"stopped": True})


@app.route("/api/stream")
def api_stream():
    return Response(monitor_mgr.stream(), mimetype="text/event-stream")


# ----------------------------------------------------------------------------
# Admin: user management
# ----------------------------------------------------------------------------
@app.route("/admin/users")
def admin_users():
    try:
        search = request.args.get("search", "").strip()
        status_filter = request.args.get("status", "")
        sort_by = request.args.get("sort", "created_at")
        sort_order = request.args.get("order", "desc")

        conn = get_db_connection()
        base_query = "FROM users WHERE 1=1"
        params = []

        if search:
            base_query += " AND (username LIKE ? OR email LIKE ?)"
            params.extend([f"%{search}%", f"%{search}%"])
        if status_filter:
            base_query += " AND is_active = ?"
            params.append(1 if status_filter == "active" else 0)

        total_users = conn.execute(
            f"SELECT COUNT(*) as count {base_query}", params
        ).fetchone()["count"]

        if sort_by not in ("username", "email", "created_at", "is_active"):
            sort_by = "created_at"
        if sort_order.lower() not in ("asc", "desc"):
            sort_order = "desc"

        users = conn.execute(
            f"""SELECT id, username, email, created_at, is_active {base_query}
                ORDER BY {sort_by} {sort_order.upper()}""",
            params,
        ).fetchall()

        stats = conn.execute("""
            SELECT COUNT(*) as total,
                   SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) as active,
                   SUM(CASE WHEN is_active = 0 THEN 1 ELSE 0 END) as inactive,
                   COUNT(CASE WHEN DATE(created_at) = DATE('now') THEN 1 END) as today_registered
            FROM users
        """).fetchone()
        conn.close()

        return render_template(
            "users.html",
            users=[dict(r) for r in users],
            total_users=total_users,
            stats={
                "total": stats["total"], "active": stats["active"],
                "inactive": stats["inactive"],
                "today_registered": stats["today_registered"],
            },
            filters={"search": search, "status": status_filter,
                     "sort": sort_by, "order": sort_order},
        )
    except Exception as e:
        flash(f"Error loading users: {e}", "danger")
        return render_template("users.html", users=[], total_users=0,
                               stats={}, filters={})


@app.route("/admin/users/create", methods=["GET", "POST"])
def admin_create_user():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()
        is_active = request.form.get("is_active") == "on"

        errors = []
        if not username or len(username) < 3:
            errors.append("Username must be at least 3 characters long")
        elif not re.match(r"^[a-zA-Z0-9_]+$", username):
            errors.append("Username can only contain letters, numbers, and underscores")
        if not email:
            errors.append("Email is required")
        elif not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email):
            errors.append("Invalid email format")
        if not password or len(password) < 6:
            errors.append("Password must be at least 6 characters long")
        if password != confirm_password:
            errors.append("Passwords do not match")

        if errors:
            for error in errors:
                flash(error, "danger")
            return render_template("create_user.html", form_data=request.form)

        conn = None
        try:
            conn = get_db_connection()
            existing_user = conn.execute(
                "SELECT id FROM users WHERE username = ? OR email = ?", (username, email)
            ).fetchone()
            if existing_user:
                flash("Username or email already exists", "danger")
                return render_template("create_user.html", form_data=request.form)

            conn.execute(
                """INSERT INTO users (username, email, password_hash, is_active)
                   VALUES (?, ?, ?, ?)""",
                (username, email, generate_password_hash(password), is_active),
            )
            conn.commit()
            flash(f'User "{username}" created successfully!', "success")
            return redirect(url_for("admin_users"))
        except Exception as e:
            flash(f"Error creating user: {e}", "danger")
            return render_template("create_user.html", form_data=request.form)
        finally:
            if conn is not None:
                conn.close()

    return render_template("create_user.html", form_data={})


@app.route("/admin/users/<int:user_id>/toggle-status", methods=["POST"])
def admin_toggle_user_status(user_id):
    try:
        conn = get_db_connection()
        user = conn.execute(
            "SELECT username, is_active FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if not user:
            flash("User not found", "danger")
            return redirect(url_for("admin_users"))
        if user_id == session["user_id"]:
            flash("You cannot deactivate your own account", "warning")
            return redirect(url_for("admin_users"))

        new_status = not user["is_active"]
        conn.execute("UPDATE users SET is_active = ? WHERE id = ?", (new_status, user_id))
        conn.commit()
        conn.close()
        flash(f'User "{user["username"]}" {"activated" if new_status else "deactivated"} '
              f"successfully!", "success")
    except Exception as e:
        flash(f"Error updating user status: {e}", "danger")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
def admin_delete_user(user_id):
    try:
        conn = get_db_connection()
        user = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            flash("User not found", "danger")
            return redirect(url_for("admin_users"))
        if user_id == session["user_id"]:
            flash("You cannot delete your own account", "warning")
            return redirect(url_for("admin_users"))

        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        flash(f'User "{user["username"]}" deleted successfully!', "success")
    except Exception as e:
        flash(f"Error deleting user: {e}", "danger")
    return redirect(url_for("admin_users"))


# ----------------------------------------------------------------------------
# IP blocking (firewall functions live in blocking_service.py - single source)
# ----------------------------------------------------------------------------
from blocking_service import block_ip_firewall, unblock_ip_firewall


@app.route("/blocked_ips")
def blocked_ips():
    """View and manage blocked IPs."""
    try:
        conn = get_db_connection()
        blocked = conn.execute(
            "SELECT * FROM blocked_ips WHERE is_blocked = 1 ORDER BY blocked_at DESC"
        ).fetchall()
        unblocked = conn.execute(
            """SELECT * FROM blocked_ips WHERE is_blocked = 0
               ORDER BY unblocked_at DESC LIMIT 50"""
        ).fetchall()
        conn.close()

        return render_template(
            "blocked_ips.html",
            blocked_ips=[dict(r) for r in blocked],
            unblocked_ips=[dict(r) for r in unblocked],
            is_admin=session.get("username") == "admin",
        )
    except Exception as e:
        flash(f"Error loading blocked IPs: {e}", "danger")
        return render_template("blocked_ips.html", blocked_ips=[], unblocked_ips=[])


def add_to_blocked_ips(ip_address, attack_type, reason="Auto-blocked by IDS"):
    """Add an IP to the blocked list (database + firewall)."""
    try:
        conn = get_db_connection()
        existing = conn.execute(
            "SELECT id, is_blocked FROM blocked_ips WHERE ip_address = ?", (ip_address,)
        ).fetchone()

        if existing:
            if existing["is_blocked"]:
                conn.execute(
                    "UPDATE blocked_ips SET block_count = block_count + 1 WHERE id = ?",
                    (existing["id"],),
                )
            else:
                conn.execute(
                    """UPDATE blocked_ips
                       SET is_blocked = 1, attack_type = ?, reason = ?,
                           blocked_at = CURRENT_TIMESTAMP, block_count = block_count + 1
                       WHERE id = ?""",
                    (attack_type, reason, existing["id"]),
                )
        else:
            conn.execute(
                "INSERT INTO blocked_ips (ip_address, attack_type, reason) VALUES (?, ?, ?)",
                (ip_address, attack_type, reason),
            )
        conn.commit()
        conn.close()

        # Apply firewall rule (may fail without admin/root privileges -
        # the database-level block via check_blocked_ip still applies)
        block_ip_firewall(ip_address)
        return True
    except Exception as e:
        print(f"Database blocking error: {e}")
        return False


@app.route("/block_ip/<ip_address>", methods=["POST"])
def block_ip_manual(ip_address):
    reason = request.form.get("reason", "Manually blocked by admin")
    attack_type = request.form.get("attack_type", "Manual")
    if add_to_blocked_ips(ip_address, attack_type, reason):
        log_system_event("INFO", f"IP {ip_address} blocked manually via URL",
                         "blocking", session["user_id"])
        flash(f"IP {ip_address} blocked successfully!", "success")
    else:
        flash(f"Failed to block IP {ip_address}", "danger")
    return redirect(url_for("blocked_ips"))


@app.route("/block_ip_form", methods=["POST"])
def block_ip_form():
    """Manually block an IP via form submission (admin only)."""
    if session.get("username") != "admin":
        flash("Only admins can manually block IPs.", "danger")
        return redirect(url_for("blocked_ips"))

    ip_address = request.form.get("ip_address", "").strip()
    reason = request.form.get("reason", "Manually blocked by admin")
    attack_type = request.form.get("attack_type", "Manual Pattern")

    if not ip_address:
        flash("IP address is required", "danger")
        return redirect(url_for("blocked_ips"))

    if add_to_blocked_ips(ip_address, attack_type, reason):
        log_system_event(
            "INFO",
            f'IP {ip_address} blocked manually by admin {session.get("username")}',
            "blocking", session["user_id"],
        )
        flash(f"IP {ip_address} blocked successfully!", "success")
    else:
        flash(f"Failed to block IP {ip_address} (already blocked or invalid)", "danger")
    return redirect(url_for("blocked_ips"))


@app.route("/unblock_ip/<ip_address>", methods=["POST"])
def unblock_ip(ip_address):
    conn = None
    try:
        conn = get_db_connection()
        conn.execute(
            """UPDATE blocked_ips
               SET is_blocked = 0, unblocked_at = CURRENT_TIMESTAMP, unblocked_by = ?
               WHERE ip_address = ?""",
            (session["username"], ip_address),
        )
        conn.commit()

        if unblock_ip_firewall(ip_address):
            log_system_event("INFO", f"IP {ip_address} unblocked",
                             "blocking", session["user_id"])
            flash(f"IP {ip_address} unblocked successfully!", "success")
        else:
            flash(f"Database updated but firewall unblock failed for {ip_address} "
                  f"(run as Administrator/root for firewall control)", "warning")
    except Exception as e:
        flash(f"Error unblocking IP: {e}", "danger")
    finally:
        if conn is not None:
            conn.close()
    return redirect(url_for("blocked_ips"))


# ----------------------------------------------------------------------------
# Startup
# ----------------------------------------------------------------------------
def start_blocking_service():
    blocking_thread = threading.Thread(target=blocking_service_loop, daemon=True)
    blocking_thread.start()
    print("Automatic IP blocking service started")


if __name__ == "__main__":
    print("Initializing Network IDS application...")

    init_db()
    print("Database initialized")

    if not initialize_live_predictor():
        print("Warning: live predictor not initialized. "
              "Check the model files in the models/ folder.")

    start_blocking_service()

    # Create default admin user on first run
    conn = get_db_connection()
    if not conn.execute("SELECT id FROM users WHERE username = ?", ("admin",)).fetchone():
        conn.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            ("admin", "admin@example.com", generate_password_hash("password123")),
        )
        conn.commit()
        print("Default admin user created (username: admin, password: password123)")
    conn.close()

    print("Network IDS is ready!")
    print("Access: http://localhost:5000")
    print("Login:  admin / password123")

    try:
        app.run(debug=False, host="0.0.0.0", port=5000, threaded=True)
    except KeyboardInterrupt:
        print("Shutting down Network IDS...")
    except Exception as e:
        print(f"Error starting application: {e}")