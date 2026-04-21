"""
app_protected.py  —  Flask app TERLINDUNGI (port 5002)

Mendemonstrasikan perbedaan antara aplikasi yang rentan (main.py :5001)
dengan aplikasi yang dilindungi middleware ML Naive Bayes.

Routes
──────
  GET        /                   → redirect ke /protected-login
  GET / POST /protected-login    → login dengan ML SQLi guard (before_request)
  GET        /blocked            → halaman "request diblokir oleh ML"
  GET        /home               → dashboard pasca-login
  GET / POST /compare            → halaman komparasi Vulnerable vs Protected
  POST       /api/predict        → JSON endpoint untuk live prediksi (AJAX)
"""

from __future__ import annotations

import logging
import sqlite3

from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from middleware import SQLiDetector

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("app_protected")

# ── App bootstrap ─────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = "protected-app-secret-key-2024"

DB_PATH = "users.db"
MODEL_PATH = "model_sqli_nb.pkl"

# Muat model sekali saat startup — error langsung terlihat
try:
    detector = SQLiDetector(MODEL_PATH)
    logger.info("Model SQLi berhasil dimuat dari %s", MODEL_PATH)
except Exception as exc:
    logger.error("Gagal memuat model: %s", exc)
    raise


# ── Database helper ───────────────────────────────────────────────────────────
def sql_connect() -> sqlite3.Connection | None:
    try:
        return sqlite3.connect(DB_PATH)
    except sqlite3.Error as err:
        logger.error("DB connection error: %s", err)
        return None


# ── SQL statement splitter (sama persis dengan main.py) ───────────────────────
def parse_statements(raw_sql: str) -> list[str]:
    """
    Pisahkan SQL mentah menjadi statement individual pada titik koma,
    sambil menghormati string literal yang di-quote tunggal.
    """
    statements: list[str] = []
    buf: list[str] = []
    in_str = False
    i = 0

    while i < len(raw_sql):
        ch = raw_sql[i]
        if in_str:
            buf.append(ch)
            if ch == "'":
                if i + 1 < len(raw_sql) and raw_sql[i + 1] == "'":
                    buf.append("'")
                    i += 1
                else:
                    in_str = False
        elif ch == "'":
            in_str = True
            buf.append(ch)
        elif ch == ";":
            stmt = "".join(buf).strip()
            if stmt:
                statements.append(stmt)
            buf = []
        else:
            buf.append(ch)
        i += 1

    tail = "".join(buf).strip()
    if tail:
        statements.append(tail)

    return statements


# ── Simulasi query rentan (untuk halaman /compare) ────────────────────────────
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
            "icon": "✅",
            "label": "True Positive",
            "msg": "Model benar — serangan SQLi terdeteksi dan diblokir.",
            "color": "hdr-green",
        }
    if ml_blocked and not any_attack:
        return {
            "type": "false_positive",
            "icon": "⚠️",
            "label": "False Positive",
            "msg": "Model salah — input sah diblokir (false alarm).",
            "color": "hdr-yellow",
        }
    if not ml_blocked and any_attack:
        return {
            "type": "false_negative",
            "icon": "❌",
            "label": "False Negative",
            "msg": "Model GAGAL — serangan lolos dari deteksi ML!",
            "color": "hdr-red",
        }
    # not blocked, no attack
    return {
        "type": "true_negative",
        "icon": "✅",
        "label": "True Negative",
        "msg": "Model benar — input sah diloloskan.",
        "color": "hdr-green",
    }


# ── Middleware: before_request SQLi guard ─────────────────────────────────────
@app.before_request
def ml_sqli_guard() -> None:
    """
    Periksa setiap field form pada endpoint protected_login.
    Jika ML mendeteksi SQLi → simpan info ke session → redirect ke /blocked.
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
            session["blocked_payload"] = value
            session["blocked_field"] = field_name
            session["blocked_confidence"] = round(confidence, 6)
            session["blocked_proba_map"] = {
                k: round(v, 6) for k, v in proba_map.items()
            }
            # Gunakan return dengan response agar Flask langsung memakai ini
            return redirect(url_for("blocked"))  # type: ignore[return-value]


# ── Routes ─────────────────────────────────────────────────────────────────────


@app.route("/")
def index():
    return redirect(url_for("protected_login"))


# ── /protected-login ──────────────────────────────────────────────────────────
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

        # Prediksi ML untuk tampilan edukatif (guard sudah jalan di before_request)
        try:
            label, confidence, proba_map = detector.predict(raw_username)
            ml_result = {
                "label": label,
                "confidence": round(confidence, 4),
                "proba_map": {k: round(v, 4) for k, v in proba_map.items()},
                "field": "username",
                "value": raw_username,
            }
        except Exception as exc:
            logger.warning("Prediksi ML gagal: %s", exc)

        # Autentikasi normal (parameterized — aman)
        conn = sql_connect()
        if conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "SELECT id FROM users WHERE username = ? AND password = ?",
                    (raw_username, raw_password),
                )
                row = cursor.fetchone()
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


# ── /blocked ──────────────────────────────────────────────────────────────────
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


# ── /home ─────────────────────────────────────────────────────────────────────
@app.route("/home")
def home():
    if "user" not in session:
        flash("Silakan login terlebih dahulu.", "warning")
        return redirect(url_for("protected_login"))
    username = session["user"]
    return render_template("home.html", username=username)


# ── /compare ──────────────────────────────────────────────────────────────────
@app.route("/compare", methods=["GET", "POST"])
def compare():
    """
    Halaman komparasi interaktif:
      - Kolom kiri  → simulasi app rentan (query dieksekusi langsung)
      - Kolom kanan → app terlindungi dengan ML middleware
    """
    result = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        # ── Prediksi ML ──────────────────────────────────────────────────────
        try:
            ml_label, ml_confidence, ml_proba_map = detector.predict(username)
        except Exception as exc:
            ml_label = "error"
            ml_confidence = 0.0
            ml_proba_map = {}
            logger.error("Prediksi ML error: %s", exc)

        ml_blocked = ml_label == "sqli"

        # ── Simulasi query rentan ─────────────────────────────────────────────
        vuln_query, vuln_results = run_vulnerable_simulation(username, password)
        vuln_bypass = check_vuln_bypass(vuln_results)

        # ── Verdict ───────────────────────────────────────────────────────────
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
        }

    return render_template("compare.html", result=result)


# ── /api/predict  (AJAX) ──────────────────────────────────────────────────────
@app.route("/api/predict", methods=["POST"])
def api_predict():
    """
    JSON endpoint untuk live prediksi saat mengetik.

    Request body (JSON):
      { "text": "<string to classify>" }

    Response:
      {
        "label":      "sqli" | "legitimate",
        "confidence": 0.0–1.0,
        "is_sqli":    true | false,
        "proba_map":  { "<class>": <prob>, ... }
      }
    """
    data = request.get_json(silent=True) or {}
    text = data.get("text", "").strip()

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


# ── /logout ───────────────────────────────────────────────────────────────────
@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Anda telah logout.", "info")
    return redirect(url_for("protected_login"))


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5002)
