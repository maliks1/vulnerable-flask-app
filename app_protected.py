"""
app_protected.py  -  Flask app TERLINDUNGI (port 5002)

Mendemonstrasikan perbedaan antara aplikasi yang rentan (main.py :5001)
dengan aplikasi yang dilindungi middleware ML Naive Bayes.

Routes
------
  GET / POST /             -> login dengan ML SQLi guard (before_request)
  GET        /home         -> dashboard pasca-login
"""

from __future__ import annotations

import logging
import os
import signal
import time
from datetime import datetime, timedelta

import pymysql
from flask import (
    Flask,
    abort,
    flash,
    g,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

# Import helper functions from centralized utils module
from config import IS_DEBUG
from middleware import SQLiDetector, preprocess_text
from utils import db_session

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger("app_protected")

# ---------------------------------------------------------------------------
# App Bootstrap
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "protected-app-secret-key-2024")


class SQLiLatencyTracker:
    """
    Class untuk melacak dan menghitung rata-rata latensi pemrosesan query SQLi.

    Attributes:
        total_latency_ms (float): Total akumulasi latensi dalam milidetik
        detection_count (int): Jumlah deteksi SQLi yang telah terjadi
        start_time (float): Waktu mulai pelacakan (epoch)
    """

    def __init__(self):
        self.total_latency_ms = 0.0
        self.detection_count = 0
        self.start_time = time.time()

    def add_latency(self, latency_ms: float) -> None:
        """Menambahkan latensi dari satu deteksi SQLi ke penghitungan."""
        self.total_latency_ms += latency_ms
        self.detection_count += 1

    def get_average_latency(self) -> float:
        """Menghitung rata-rata latensi dalam milidetik."""
        if self.detection_count == 0:
            return 0.0
        return self.total_latency_ms / self.detection_count

    def get_summary(self) -> str:
        """Mengembalikan string ringkasan dalam format yang ditentukan."""
        avg = self.get_average_latency()
        runtime_seconds = time.time() - self.start_time
        runtime_formatted = str(timedelta(seconds=int(runtime_seconds)))
        return f"Rata-rata latensi SQLi: {avg:.2f} ms (dari {self.detection_count} deteksi) - Runtime: {runtime_formatted}"


MODEL_PATH = "model_sqli_nb.pkl"

# Initialize SQLi latency tracker
sqli_latency_tracker = SQLiLatencyTracker()


def shutdown_handler(signum, frame) -> None:
    """Handler untuk sinyal shutdown (Ctrl+C)."""
    # Unregister handler first to prevent duplicate calls
    signal.signal(signum, signal.SIG_DFL)
    logger.info("Shutdown signal received, writing SQLi latency log...")
    summary = sqli_latency_tracker.get_summary()
    write_latency_log(summary)
    # Re-raise the signal to allow normal shutdown
    os.kill(os.getpid(), signum)


# Set up signal handlers
signal.signal(signal.SIGINT, shutdown_handler)
signal.signal(signal.SIGTERM, shutdown_handler)

# Muat model sekali saat startup - error langsung terlihat
try:
    detector = SQLiDetector(MODEL_PATH)
    if IS_DEBUG == "1":
        logger.info("Model SQLi berhasil dimuat dari %s", MODEL_PATH)
except Exception as exc:
    logger.error("Gagal memuat model: %s", exc)
    raise


@app.context_processor
def inject_debug_flag():
    return {"IS_DEBUG": IS_DEBUG}


# ---------------------------------------------------------------------------
# Middleware: before_request SQLi guard
# ---------------------------------------------------------------------------
@app.before_request
def init_request_timing():
    if IS_DEBUG != "1":
        return

    g.request_start_time = time.perf_counter()

    g.sqli_metrics = {
        "pre_filter_ms": 0.0,
        "ml_ms": 0.0,
        "db_ms": 0.0,
        "decision_ms": 0.0,
        "total_ms": 0.0,
        "username_val": request.form.get("username", ""),
        "password_val": request.form.get("password", ""),
    }


@app.before_request
def ml_sqli_guard() -> None:
    """
    Periksa setiap field form pada endpoint index.
    Jika ML mendeteksi SQLi -> simpan info ke session -> abort 403.
    """
    if request.endpoint != "index" or request.method != "POST":
        return  # hanya aktif di POST /

    fields_to_check = [
        ("username", request.form.get("username", "")),
        ("password", request.form.get("password", "")),
    ]

    # Reset stage timings at the start of this guard so accumulated values
    # from any stale state cannot leak in. We use interval-based timings
    # measured from g.request_start_time so the sum of stages is consistent
    # with the final total_ms computed in after_request.
    if IS_DEBUG == "1" and hasattr(g, "sqli_metrics"):
        g.sqli_metrics["pre_filter_ms"] = 0.0
        g.sqli_metrics["ml_ms"] = 0.0
        g.sqli_metrics["decision_ms"] = 0.0
        g.sqli_metrics["blocked"] = False

    for field_name, value in fields_to_check:
        if not value:
            continue
        try:
            _t_ml0 = time.perf_counter()
            label, confidence, proba_map = detector.predict(value)
            _t_ml1 = time.perf_counter()
            if IS_DEBUG == "1" and hasattr(g, "sqli_metrics"):
                # Pure ML inference time (delta), accumulated across fields.
                g.sqli_metrics["ml_ms"] = (
                    g.sqli_metrics.get("ml_ms", 0.0) + (_t_ml1 - _t_ml0) * 1000.0
                )
        except Exception as exc:
            if IS_DEBUG == "1":
                logger.warning("Prediksi gagal untuk field '%s': %s", field_name, exc)
            continue

        if label == "sqli":
            if (
                IS_DEBUG == "1"
                and hasattr(g, "request_start_time")
                and hasattr(g, "sqli_metrics")
            ):
                t_now = time.perf_counter()
                # decision_ms = full elapsed from request start to block
                # decision. Includes pre_filter + all ml predicts.
                g.sqli_metrics["decision_ms"] = (t_now - g.request_start_time) * 1000.0
                g.sqli_metrics["blocked"] = True

            # Record latency for SQLi detection
            if hasattr(g, "request_start_time"):
                total_latency_ms = (time.perf_counter() - g.request_start_time) * 1000.0
                sqli_latency_tracker.add_latency(total_latency_ms)

            # Keep metrics in session so we can display them on 403 or redirect
            if IS_DEBUG == "1":
                session["sqli_metrics"] = g.sqli_metrics

            # Abort with 403 so Flask dispatches to the custom errorhandler(403)
            # which renders templates/403.html with the collected metrics.
            abort(403)
        # end for field
    # end def


# ---------------------------------------------------------------------------
# Lifecycle: hitung total_ms SETELAH response body selesai di-render
# (sama dengan titik ukur di main.py agar perbandingan apples-to-apples)
# ---------------------------------------------------------------------------
@app.after_request
def log_request_latency(response):
    """
    Finalise total_ms AFTER the response body is fully rendered, then emit the
    telemetry block. Runs for both ALLOWED and BLOCKED paths (Flask invokes
    after_request even when the response originated from an error handler).
    """
    if IS_DEBUG != "1":
        return response
    if not hasattr(g, "request_start_time"):
        return response
    if not hasattr(g, "sqli_metrics"):
        return response
    if request.path.startswith("/static/"):
        return response

    metrics = g.sqli_metrics
    if metrics.get("blocked"):
        # For blocked path: total = sum of measured stages. No DB stage, so
        # pre_filter + ml + decision == total.
        total_ms = (
            metrics.get("pre_filter_ms", 0.0)
            + metrics.get("ml_ms", 0.0)
            + metrics.get("decision_ms", 0.0)
        )
    else:
        # For allowed path: total includes DB + everything up to after_request.
        total_ms = (time.perf_counter() - g.request_start_time) * 1000.0
    metrics["total_ms"] = total_ms

    if metrics.get("blocked"):
        username_preprocessed = preprocess_text(metrics.get("username_val", ""))
        password_preprocessed = preprocess_text(metrics.get("password_val", ""))
        logger.info(
            "\n"
            "============================================================\n"
            " [TELEMETRY] BLOCKED SQL INJECTION INTRUSION\n"
            "------------------------------------------------------------\n"
            " Query Pre-Filter Check : %.4f ms\n"
            " ML Model Prediction    : %.4f ms\n"
            " Blocking Decision Made : %.4f ms\n"
            "------------------------------------------------------------\n"
            " Total Backend Latency  : %.4f ms\n"
            " Sent Input Username    : %s\n"
            " (Debugging) Username After Preprocessing : %s\n"
            " Sent Input Password    : %s\n"
            " (Debugging) Password After Preprocessing : %s\n"
            "============================================================",
            metrics.get("pre_filter_ms", 0.0),
            metrics.get("ml_ms", 0.0),
            metrics.get("decision_ms", 0.0),
            total_ms,
            metrics.get("username_val", ""),
            username_preprocessed,
            metrics.get("password_val", ""),
            password_preprocessed,
        )

    return response


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.route("/", methods=["GET", "POST"])
def index():
    """
    Login yang dijaga middleware ML.
    Jika request POST sampai di sini, berarti ML sudah meloloskannya.
    Tampilkan hasil prediksi ML + hasil autentikasi normal.
    """
    ml_result = None
    raw_username = ""
    raw_password = ""
    login_ok = False

    if request.method == "POST":
        raw_username = request.form.get("username", "")
        raw_password = request.form.get("password", "")
        t_pre_start = time.perf_counter()
        username_preprocessed = preprocess_text(raw_username)
        password_preprocessed = preprocess_text(raw_password)
        t_pre_end = time.perf_counter()
        pre_filter_ms = (t_pre_end - t_pre_start) * 1000.0
        if IS_DEBUG == "1" and hasattr(g, "sqli_metrics"):
            g.sqli_metrics["pre_filter_ms"] = pre_filter_ms

        # Prediksi ML untuk tampilan edukatif (guard sudah jalan di before_request)
        try:
            t_ml_start = time.perf_counter()
            label, confidence, proba_map = detector.predict(raw_username)
            t_ml_end = time.perf_counter()
            ml_ms = (t_ml_end - t_ml_start) * 1000.0

            if IS_DEBUG == "1" and hasattr(g, "sqli_metrics"):
                g.sqli_metrics["ml_ms"] = g.sqli_metrics.get("ml_ms", 0.0) + ml_ms
                g.sqli_metrics["decision_ms"] = (
                    t_ml_end - g.request_start_time
                ) * 1000.0
            ml_result = {
                "label": label,
                "confidence": round(confidence, 4),
                "proba_map": {k: round(v, 4) for k, v in proba_map.items()},
                "field": "username",
                "value": raw_username,
            }
        except Exception as exc:
            if IS_DEBUG == "1":
                logger.warning("Prediksi ML gagal: %s", exc)

        # Autentikasi normal (parameterized - aman)
        row = None
        try:
            t_db_start = time.perf_counter()
            with db_session() as conn:
                if conn:
                    cursor = conn.cursor()
                    try:
                        cursor.execute(
                            "SELECT id FROM users WHERE username = %s AND password = %s",
                            (raw_username, raw_password),
                        )
                        row = cursor.fetchone()
                    finally:
                        cursor.close()
            t_db_end = time.perf_counter()
            db_ms = (t_db_end - t_db_start) * 1000.0

            if IS_DEBUG == "1" and hasattr(g, "sqli_metrics"):
                g.sqli_metrics["db_ms"] = db_ms
                t_now = time.perf_counter()
                total_ms = (t_now - g.request_start_time) * 1000.0
                g.sqli_metrics["total_ms"] = total_ms

                if IS_DEBUG == "1":
                    # Log timing breakdown to console
                    logger.info(
                        "\n"
                        "============================================================\n"
                        " [TELEMETRY] ALLOWED REQUEST (ZERO-TRUST PASSED)\n"
                        "------------------------------------------------------------\n"
                        " Query Pre-Filter Check : %.4f ms\n"
                        " ML Model Prediction    : %.4f ms\n"
                        " Database Query Exec    : %.4f ms\n"
                        "------------------------------------------------------------\n"
                        " Total Backend Latency  : %.4f ms\n"
                        " Sent Input Username    : %s\n"
                        " (Debugging) Username After Preprocessing : %s\n"
                        " Sent Input Password    : %s\n"
                        " (Debugging) Password After Preprocessing : %s\n"
                        "============================================================",
                        g.sqli_metrics.get("pre_filter_ms", 0.0),
                        g.sqli_metrics.get("ml_ms", 0.0),
                        db_ms,
                        total_ms,
                        g.sqli_metrics.get("username_val", ""),
                        username_preprocessed,
                        g.sqli_metrics.get("password_val", ""),
                        password_preprocessed,
                    )
                    if row:
                        session["user"] = raw_username
                        login_ok = True
                        flash("Login berhasil!", "success")
                    else:
                        flash("Username atau password salah.", "danger")
        except pymysql.Error as exc:
            flash(f"Database error: {exc}", "danger")

        if login_ok:
            return redirect(url_for("home"))

    resp = make_response(
        render_template(
            "protected_login.html",
            ml_result=ml_result,
            raw_username=raw_username,
            raw_password=raw_password,
        )
    )
    if IS_DEBUG == "1" and hasattr(g, "sqli_metrics"):
        resp.headers["X-Metrics-Total-Ms"] = (
            f"{g.sqli_metrics.get('total_ms', 0.0):.4f}"
        )
        resp.headers["X-Metrics-DB-Ms"] = f"{g.sqli_metrics.get('db_ms', 0.0):.4f}"
        resp.headers["X-Metrics-ML-Ms"] = f"{g.sqli_metrics.get('ml_ms', 0.0):.4f}"
        resp.headers["X-Metrics-Stage"] = "allowed_login"
    return resp


@app.route("/home")
def home():
    if "user" not in session:
        flash("Silakan login terlebih dahulu.", "warning")
        return redirect(url_for("index"))
    username = session["user"]
    return render_template("home.html", username=username)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Anda telah logout.", "info")
    return redirect(url_for("index"))


# Custom 403 Forbidden Error Handler
@app.errorhandler(403)
def forbidden_error(error):
    """Custom error handler for HTTP 403 Forbidden."""
    # Prefer live g.sqli_metrics (same request context) so all timings -
    # including pre_filter_ms, ml_ms, decision_ms set in before_request -
    # reach the template. Fall back to session for cross-request cases.
    metrics = None
    if IS_DEBUG == "1":
        if hasattr(g, "sqli_metrics") and g.sqli_metrics:
            metrics = g.sqli_metrics
        else:
            metrics = session.get("sqli_metrics")
    if IS_DEBUG == "1" and metrics and hasattr(g, "request_start_time"):
        # Finalise total_ms NOW, before rendering 403.html. after_request
        # runs AFTER the view/error handler returns, so it cannot help us
        # populate the template that is rendered right here.
        metrics["total_ms"] = (time.perf_counter() - g.request_start_time) * 1000.0
        # Persist final value back to g so after_request sees it.
        g.sqli_metrics["total_ms"] = metrics["total_ms"]
    response = make_response(
        render_template("403.html", metrics=metrics, IS_DEBUG=IS_DEBUG), 403
    )
    if IS_DEBUG == "1" and metrics:
        response.headers["X-Metrics-Total-Ms"] = f"{metrics.get('total_ms', 0.0):.4f}"
        response.headers["X-Metrics-Stage"] = "blocked_403"
    return response


def write_latency_log(summary: str) -> None:
    """Fungsi untuk menulis log ke file."""
    log_dir = "logs"
    log_file = os.path.join(log_dir, "sqli_latency.log")

    # Create logs directory if it doesn't exist
    os.makedirs(log_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {summary}\n"

    with open(log_file, "a", encoding="utf-8") as f:
        f.write(log_entry)

    logger.info("SQLi latency log written: %s", summary)


if __name__ == "__main__":
    app.run(debug=(IS_DEBUG == "1"), host="0.0.0.0", port=5002)
