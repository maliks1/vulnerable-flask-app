"""
app_protected.py  -  Flask app TERLINDUNGI (port 5002)

Mendemonstrasikan perbedaan antara aplikasi yang rentan (main.py :5001)
dengan aplikasi yang dilindungi middleware ML Naive Bayes.

Routes
------
  GET        /                   -> redirect ke /protected-login
  GET / POST /protected-login    -> login dengan ML SQLi guard (before_request)
  GET        /blocked            -> halaman "request diblokir oleh ML"
  GET        /home               -> dashboard pasca-login
  GET / POST /compare            -> halaman komparasi Vulnerable vs Protected
  POST       /api/predict        -> JSON endpoint untuk live prediksi (AJAX)
"""

from __future__ import annotations

import logging
import sqlite3
import json
from datetime import datetime
import time
import os

from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
    abort,
    g
)

# Import helper functions from centralized utils module
from utils import sql_connect, parse_statements
from middleware import SQLiDetector, preprocess_text

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

MODEL_PATH = "model_sqli_nb.pkl"

# Muat model sekali saat startup - error langsung terlihat
try:
    detector = SQLiDetector(MODEL_PATH)
    logger.info("Model SQLi berhasil dimuat dari %s", MODEL_PATH)
except Exception as exc:
    logger.error("Gagal memuat model: %s", exc)
    raise


# ---------------------------------------------------------------------------
# Simulasi query rentan (untuk halaman /compare)
# ---------------------------------------------------------------------------
def run_vulnerable_simulation(username: str, password: str) -> tuple[str, list[dict]]:
    """
    Jalankan query TIDAK AMAN persis seperti main.py.
    Digunakan HANYA untuk tujuan edukatif di halaman /compare.
    Return: (query_string, list_of_result_dicts)
    """
    login_query = (
        f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    )
    results: list[dict] = []
    conn = sql_connect()

    if conn is None:
        return login_query, results

    cursor = conn.cursor()
    try:
        for stmt in parse_statements(login_query):
            entry: dict = {
                "stmt": stmt,
                "columns": [],
                "rows": [],
                "rowcount": None,
                "error": None,
            }
            try:
                cursor.execute(stmt)
                if cursor.description:
                    entry["columns"] = [d[0] for d in cursor.description]
                    entry["rows"] = [list(r) for r in cursor.fetchall()]
                else:
                    conn.commit()
                    entry["rowcount"] = cursor.rowcount
            except sqlite3.Error as exc:
                entry["error"] = str(exc)
            results.append(entry)
    finally:
        cursor.close()
        conn.close()

    return login_query, results


def check_vuln_bypass(results: list[dict]) -> bool:
    """True jika ada SELECT yang mengembalikan baris (login bypass)."""
    first_select = next(
        (e for e in results if e["columns"] and not e["error"]),
        None,
    )
    return bool(first_select and first_select["rows"])


def classify_verdict(
    ml_blocked: bool, vuln_bypass: bool, vuln_results: list[dict]
) -> dict:
    """
    Hasilkan verdict edukatif berdasarkan prediksi ML vs perilaku query rentan.
    """
    # Deteksi apakah ada statement DML/DDL yang berhasil
    has_dml = any(
        e["rowcount"] is not None
        and not e["error"]
        and any(
            e["stmt"].strip().upper().startswith(kw)
            for kw in ("INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER")
        )
        for e in vuln_results
    )
    any_attack = vuln_bypass or has_dml

    if ml_blocked and any_attack:
        return {
            "type": "true_positive",
            "icon": "check-circle",
            "label": "True Positive",
            "msg": "Model benar - serangan SQLi terdeteksi dan diblokir.",
            "color": "hdr-green",
        }
    if ml_blocked and not any_attack:
        return {
            "type": "false_positive",
            "icon": "alert-triangle",
            "label": "False Positive",
            "msg": "Model salah - input sah diblokir (false alarm).",
            "color": "hdr-yellow",
        }
    if not ml_blocked and any_attack:
        return {
            "type": "false_negative",
            "icon": "x-circle",
            "label": "False Negative",
            "msg": "Model GAGAL - serangan lolos dari deteksi ML!",
            "color": "hdr-red",
        }
    # not blocked, no attack
    return {
        "type": "true_negative",
        "icon": "check-circle",
        "label": "True Negative",
        "msg": "Model benar - input sah diloloskan.",
        "color": "hdr-green",
    }


# ---------------------------------------------------------------------------
# Middleware: before_request SQLi guard
# ---------------------------------------------------------------------------
@app.before_request
def init_request_timing():
    g.request_start_time = time.perf_counter()
    g.request_start_epoch = time.time()
    
    # Client send time (in ms since epoch)
    client_time_ms = request.form.get("_client_sent_time") or request.headers.get("X-Client-Sent-Time")
    g.client_sent_time = None
    g.network_ms = 0.0
    if client_time_ms:
        try:
            g.client_sent_time = float(client_time_ms) / 1000.0 # convert ms to seconds
            # Calculate network latency: request arrival epoch minus client send epoch
            network_diff = g.request_start_epoch - g.client_sent_time
            if network_diff > 0:
                g.network_ms = network_diff * 1000.0
        except Exception:
            pass
            
    g.sqli_metrics = {
        "network_ms": g.network_ms,
        "pre_filter_ms": 0.0,
        "ml_ms": 0.0,
        "db_ms": 0.0,
        "decision_ms": 0.0,
        "total_ms": 0.0,
        "username_val": request.form.get("username", ""),
        "password_val": request.form.get("password", "")
    }

@app.before_request
def ml_sqli_guard() -> None:
    """
    Periksa setiap field form pada endpoint protected_login.
    Jika ML mendeteksi SQLi -> simpan info ke session -> redirect ke /blocked.
    """
    if request.endpoint != "protected_login" or request.method != "POST":
        return  # hanya aktif di POST /protected-login

    fields_to_check = [
        ("username", request.form.get("username", "")),
        ("password", request.form.get("password", "")),
    ]

    for field_name, value in fields_to_check:
        if not value:
            continue
        try:
            label, confidence, proba_map = detector.predict(value)
        except Exception as exc:
            logger.warning("Prediksi gagal untuk field '%s': %s", field_name, exc)
            continue

        logger.info(
            "[GUARD] field=%s | label=%s | confidence=%.4f | value=%.60r",
            field_name,
            label,
            confidence,
            value,
        )

        if label == "sqli":
            # Forensic logging: timestamp, client IP, payload, confidence, proba_map
            client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
            timestamp = datetime.utcnow().isoformat() + "Z"
            try:
                proba_serial = json.dumps({k: round(v, 6) for k, v in proba_map.items()})
            except Exception:
                proba_serial = str(proba_map)

            # Calculate blocking decision latency
            if hasattr(g, 'request_start_time') and hasattr(g, 'sqli_metrics'):
                t_now = time.perf_counter()
                decision_ms = (t_now - g.request_start_time) * 1000.0
                g.sqli_metrics["decision_ms"] = decision_ms
                g.sqli_metrics["total_ms"] = decision_ms

            logger.warning(
                "[FORNSIC] time=%s ip=%s field=%s confidence=%.6f payload=%r proba=%s",
                timestamp,
                client_ip,
                field_name,
                float(confidence),
                value,
                proba_serial,
            )

            # Log timing breakdown to console
            t_total = g.sqli_metrics.get("total_ms", 0.0)
            t_pre = g.sqli_metrics.get("pre_filter_ms", 0.0)
            t_ml = g.sqli_metrics.get("ml_ms", 0.0)
            t_dec = g.sqli_metrics.get("decision_ms", 0.0)
            t_net = g.sqli_metrics.get("network_ms", 0.0)
            username_preprocessed = preprocess_text(g.sqli_metrics.get("username_val", ""))
            password_preprocessed = preprocess_text(g.sqli_metrics.get("password_val", ""))
            logger.info(
                "\n"
                "============================================================\n"
                " [TELEMETRY] BLOCKED SQL INJECTION INTRUSION\n"
                "------------------------------------------------------------\n"
                " Client Send Epoch      : %s\n"
                " HTTP Request Arrival   : [OK] (Net Latency: %.4f ms)\n"
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
                g.client_sent_time if g.client_sent_time else "N/A",
                t_net, t_pre, t_ml, t_dec, t_total,
                g.sqli_metrics.get("username_val", ""),
                username_preprocessed,
                g.sqli_metrics.get("password_val", ""),
                password_preprocessed,
            )

            # Keep metrics in session so we can display them on 403 or redirect
            session["sqli_metrics"] = g.sqli_metrics

            # Kembalikan HTTP 403 Forbidden sebagai aksi blok
            abort(403)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return redirect(url_for("protected_login"))


@app.route("/protected-login", methods=["GET", "POST"])
def protected_login():
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
        username_preprocessed = preprocess_text(raw_username)
        password_preprocessed = preprocess_text(raw_password)

        # Prediksi ML untuk tampilan edukatif (guard sudah jalan di before_request)
        try:
            t_ml_start = time.perf_counter()
            label, confidence, proba_map = detector.predict(raw_username)
            t_ml_end = time.perf_counter()
            ml_ms = (t_ml_end - t_ml_start) * 1000.0
            
            if hasattr(g, 'sqli_metrics'):
                g.sqli_metrics['ml_ms'] = ml_ms
                g.sqli_metrics['decision_ms'] = (t_ml_end - g.request_start_time) * 1000.0
            ml_result = {
                "label": label,
                "confidence": round(confidence, 4),
                "proba_map": {k: round(v, 4) for k, v in proba_map.items()},
                "field": "username",
                "value": raw_username,
            }
        except Exception as exc:
            logger.warning("Prediksi ML gagal: %s", exc)

        # Autentikasi normal (parameterized - aman)
        conn = sql_connect()
        if conn:
            cursor = conn.cursor()
            try:
                t_db_start = time.perf_counter()
                cursor.execute(
                    "SELECT id FROM users WHERE username = ? AND password = ?",
                    (raw_username, raw_password),
                )
                row = cursor.fetchone()
                t_db_end = time.perf_counter()
                db_ms = (t_db_end - t_db_start) * 1000.0
                
                if hasattr(g, 'sqli_metrics'):
                    g.sqli_metrics['db_ms'] = db_ms
                    t_now = time.perf_counter()
                    total_ms = (t_now - g.request_start_time) * 1000.0
                    g.sqli_metrics['total_ms'] = total_ms
                    
                    # Log timing breakdown to console
                    logger.info(
                        "\n"
                        "============================================================\n"
                        " [TELEMETRY] ALLOWED REQUEST (ZERO-TRUST PASSED)\n"
                        "------------------------------------------------------------\n"
                        " HTTP Request Arrival   : [OK] (Net Latency: %.4f ms)\n"
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
                        g.sqli_metrics.get("network_ms", 0.0),
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
            except sqlite3.Error as exc:
                flash(f"Database error: {exc}", "danger")
            finally:
                cursor.close()
                conn.close()

        if login_ok:
            return redirect(url_for("home"))

    return render_template(
        "protected_login.html",
        ml_result=ml_result,
        raw_username=raw_username,
        raw_password=raw_password,
    )


@app.route("/blocked")
def blocked():
    """Halaman ditampilkan saat middleware ML memblokir request."""
    payload = session.pop("blocked_payload", "N/A")
    field = session.pop("blocked_field", "unknown")
    confidence = session.pop("blocked_confidence", 0.0)
    proba_map = session.pop("blocked_proba_map", {})

    return render_template(
        "blocked.html",
        payload=payload,
        field=field,
        confidence=confidence,
        proba_map=proba_map,
    )


@app.route("/home")
def home():
    if "user" not in session:
        flash("Silakan login terlebih dahulu.", "warning")
        return redirect(url_for("protected_login"))
    username = session["user"]
    return render_template("home.html", username=username)


@app.route("/compare", methods=["GET", "POST"])
def compare():
    """
    Halaman komparasi interaktif:
      - Kolom kiri  -> simulasi app rentan (query dieksekusi langsung)
      - Kolom kanan -> app terlindungi dengan ML middleware
    """
    result = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # Catat waktu awal request simulasi
        t_req_start = time.perf_counter()
        
        # Prediksi ML
        try:
            t_ml_start = time.perf_counter()
            ml_label, ml_confidence, ml_proba_map = detector.predict(username)
            t_ml_end = time.perf_counter()
            ml_total_ms = (t_ml_end - t_ml_start) * 1000.0
        except Exception as exc:
            ml_label = "error"
            ml_confidence = 0.0
            ml_proba_map = {}
            ml_total_ms = 0.0
            logger.error("Prediksi ML error: %s", exc)

        ml_blocked = ml_label == "sqli"

        # Simulasi query rentan
        t_sql_start = time.perf_counter()
        vuln_query, vuln_results = run_vulnerable_simulation(username, password)
        t_sql_end = time.perf_counter()
        sql_total_ms = (t_sql_end - t_sql_start) * 1000.0
        
        vuln_bypass = check_vuln_bypass(vuln_results)

        # Verdict
        verdict = classify_verdict(ml_blocked, vuln_bypass, vuln_results)

        result = {
            # input
            "username": username,
            "password": password,
            # ML
            "ml_label": ml_label,
            "ml_confidence": round(ml_confidence, 4),
            "ml_proba_map": {k: round(v, 4) for k, v in ml_proba_map.items()},
            "ml_blocked": ml_blocked,
            # Vulnerable sim
            "vuln_query": vuln_query,
            "vuln_results": vuln_results,
            "vuln_bypass": vuln_bypass,
            # Verdict
            "verdict": verdict,
            # Telemetry comparison
            "ml_latency_ms": round(ml_total_ms, 3),
            "sql_latency_ms": round(sql_total_ms, 3),
            "pre_filter_ms": round(g.sqli_metrics.get("pre_filter_ms", 0.0), 3) if hasattr(g, 'sqli_metrics') else 0.0,
            "ml_model_ms": round(g.sqli_metrics.get("ml_ms", 0.0), 3) if hasattr(g, 'sqli_metrics') else 0.0,
        }

    return render_template("compare.html", result=result)


@app.route("/api/predict", methods=["POST"])
def api_predict():
    """
    JSON endpoint untuk live prediksi saat mengetik.
    """
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")

    if not text:
        return jsonify({"error": "Field 'text' wajib diisi."}), 400

    try:
        label, confidence, proba_map = detector.predict(text)
    except Exception as exc:
        logger.error("/api/predict error: %s", exc)
        return jsonify({"error": str(exc)}), 500

    return jsonify(
        {
            "label": label,
            "confidence": round(confidence, 6),
            "is_sqli": label == "sqli",
            "proba_map": {k: round(v, 6) for k, v in proba_map.items()},
        }
    )


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Anda telah logout.", "info")
    return redirect(url_for("protected_login"))


# Custom 403 Forbidden Error Handler
@app.errorhandler(403)
def forbidden_error(error):
    """Custom error handler for HTTP 403 Forbidden."""
    metrics = session.pop("sqli_metrics", None)
    if not metrics and hasattr(g, 'sqli_metrics'):
        metrics = g.sqli_metrics
        if hasattr(g, 'request_start_time'):
            decision_ms = (time.perf_counter() - g.request_start_time) * 1000.0
            metrics['decision_ms'] = decision_ms
            metrics['total_ms'] = decision_ms
    return render_template('403.html', metrics=metrics), 403


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5002)
