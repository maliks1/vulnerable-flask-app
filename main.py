import logging
import os
import subprocess
import sys
import time
from contextlib import contextmanager

import pymysql
import pymysql.constants
from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from pymysql.constants import CLIENT

IS_DEBUG = os.environ.get("IS_DEBUG", "1")

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger("main")


MYSQL_CONFIG = {
    "host": "127.0.0.1",
    "port": 3306,
    "user": "root",
    "password": "",
    "database": "users",
}


def sql_connect() -> pymysql.connections.Connection | None:
    try:
        return pymysql.connect(
            host=MYSQL_CONFIG["host"],
            port=MYSQL_CONFIG["port"],
            user=MYSQL_CONFIG["user"],
            password=MYSQL_CONFIG["password"],
            database=MYSQL_CONFIG["database"],
            # INI KUNCINYA: Mengizinkan Stacked Queries, Time-Based, dan SP dieksekusi native
            client_flag=CLIENT.MULTI_STATEMENTS,
        )
    except pymysql.Error as err:
        if IS_DEBUG == "1":
            print(f"[DB ERROR] {err}")
        return None


@contextmanager
def db_session():
    conn = sql_connect()
    try:
        yield conn
    finally:
        if conn:
            conn.close()


app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "fallback-vulnerable-key-2024")


@app.context_processor
def inject_debug_flag():
    return {"IS_DEBUG": IS_DEBUG}


@app.before_request
def init_request_timing():
    if IS_DEBUG != "1":
        return

    g.request_start_time = time.perf_counter()

    g.sqli_metrics = {
        "db_ms": 0.0,
        "total_ms": 0.0,
        "view_ms": 0.0,
    }


@app.route("/home")
def home():
    if "user" not in session:
        flash("Silakan login terlebih dahulu.", "warning")
        return redirect(url_for("login"))
    return render_template("vulnerable_home.html", username=session["user"])


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Anda telah logout.", "info")
    return redirect(url_for("login"))


@app.route("/", methods=["GET", "POST"])
def login():
    # Stopwatch view: mulai tepat saat Flask memanggil fungsi ini.
    # Tidak termasuk middleware, tidak termasuk after_request hook.
    _view_t0 = time.perf_counter()
    executed_query = None
    auth_status = "idle"
    db_username = None
    sql_error_message = None
    query_columns, query_rows = [], []
    raw_username, raw_password = "", ""

    if request.method == "POST":
        raw_username = request.form.get("username", "")
        raw_password = request.form.get("password", "")
        g.sqli_metrics["raw_username"] = raw_username
        g.sqli_metrics["raw_password"] = raw_password
        g.sqli_metrics["pre_username"] = raw_username
        g.sqli_metrics["pre_password"] = raw_password

        # VULN: String concatenation murni tanpa filter apapun
        login_query = f"SELECT * FROM users WHERE username = '{raw_username}' AND password = '{raw_password}'"
        executed_query = login_query

        try:
            t_db_start = time.perf_counter()
            with db_session() as conn:
                if conn is None:
                    auth_status = "error"
                    sql_error_message = "Database connection failed."
                else:
                    with conn.cursor(pymysql.cursors.DictCursor) as cursor:
                        if IS_DEBUG == "1":
                            print(f"[SQLI EXEC] {login_query}")

                        # FIX: EKSEKUSI NATIVE MURNI.
                        # Tidak ada parsing, tidak ada split, tidak ada is_sp.
                        # Biarkan pymysql menangani MULTI_STATEMENTS secara otomatis.
                        try:
                            cursor.execute(login_query)
                        finally:
                            t_db_end = time.perf_counter()
                            db_ms = (t_db_end - t_db_start) * 1000.0
                            if IS_DEBUG == "1" and hasattr(g, "sqli_metrics"):
                                g.sqli_metrics["db_ms"] = db_ms

                        first_row = None
                        if cursor.description:
                            rs = cursor.fetchall()
                            if rs:
                                first_row = rs[0]
                                query_columns = [d[0] for d in cursor.description]

                        # FIX: Loop nextset() untuk menangkap hasil Stacked Queries
                        # (Misal: sqlmap mengirim ' ; SELECT SLEEP(5) --)
                        while cursor.nextset():
                            if cursor.description:
                                rs = cursor.fetchall()
                                if rs and not first_row:
                                    first_row = rs[0]
                                    query_columns = [d[0] for d in cursor.description]

                        query_rows = (
                            [list(first_row.values())]
                            if first_row and isinstance(first_row, dict)
                            else [list(first_row)]
                            if first_row
                            else []
                        )

                        conn.commit()

                        if "user" not in session and first_row:
                            auth_status = "success"
                            if isinstance(first_row, dict):
                                db_username = first_row.get("username") or (
                                    list(first_row.values())[1]
                                    if len(first_row) > 1
                                    else list(first_row.values())[0]
                                )
                            else:
                                db_username = (
                                    first_row[query_columns.index("username")]
                                    if "username" in query_columns
                                    else (
                                        first_row[1]
                                        if len(first_row) > 1
                                        else first_row[0]
                                    )
                                )
                            db_username = str(db_username)
                            session["user"] = db_username
                            flash(f"Login berhasil! Welcome, {db_username}", "success")
                            g.sqli_metrics["view_ms"] = (
                                time.perf_counter() - _view_t0
                            ) * 1000.0
                            return redirect(url_for("home"))
                        elif "user" not in session:
                            auth_status = "failed"
                            flash(
                                "Login gagal: username/password tidak valid.", "danger"
                            )

        except pymysql.Error as exc:
            auth_status = "error"
            sql_error_message = str(exc)
            executed_query = f"{executed_query} -- [SQL ERROR] {sql_error_message}"
            flash(f"Database Error: {sql_error_message}", "danger")
            if IS_DEBUG == "1":
                print(f"[SQL ERROR] {exc}")

    g.sqli_metrics["view_ms"] = (time.perf_counter() - _view_t0) * 1000.0
    return render_template(
        "login.html",
        executed_query=executed_query,
        auth_status=auth_status,
        db_username=db_username,
        sql_error_message=sql_error_message,
        query_columns=query_columns,
        query_rows=query_rows,
        raw_username=raw_username,
        raw_password=raw_password,
    )


def _print_telemetry_block(response):
    if IS_DEBUG != "1":
        return
    if not hasattr(g, "sqli_metrics"):
        return

    # Skip GET: no DB execution, no input payload. POST (including 302
    # redirect-after-success) is always logged.
    if request.method == "GET":
        return

    metrics = g.sqli_metrics
    db_ms = metrics.get("db_ms", 0.0)
    total_ms = metrics.get("total_ms", 0.0)

    raw_user = metrics.get("raw_username", "")
    raw_pass = metrics.get("raw_password", "")

    bar = "=" * 60
    sub = "-" * 60
    print(bar)
    print(" [TELEMETRY] WEB VULNERABLE LOG")
    print(sub)
    print(f" Database Query Exec    : {db_ms:.4f} ms")
    print(sub)
    print(f" Total Backend Latency  : {total_ms:.4f} ms")
    print(f" Sent Input Username    : {raw_user}")
    print(f" Sent Input Password    : {raw_pass}")
    print(bar)


@app.after_request
def log_request_latency(response):
    if IS_DEBUG != "1":
        return response
    if not hasattr(g, "request_start_time"):
        return response
    if not hasattr(g, "sqli_metrics"):
        return response
    if request.path.startswith("/static/"):
        return response

    total_ms = (time.perf_counter() - g.request_start_time) * 1000.0
    g.sqli_metrics["total_ms"] = total_ms
    _print_telemetry_block(response)
    response.headers["X-Metrics-Total-Ms"] = f"{total_ms:.4f}"
    response.headers["X-Metrics-DB-Ms"] = f"{g.sqli_metrics.get('db_ms', 0.0):.4f}"
    response.headers["X-Metrics-View-Ms"] = f"{g.sqli_metrics.get('view_ms', 0.0):.4f}"
    response.headers["X-Metrics-Stage"] = "vulnerable_login"
    return response


if __name__ == "__main__":
    protected_script = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "app_protected.py"
    )
    protected_proc = subprocess.Popen([sys.executable, protected_script])
    if IS_DEBUG == "1":
        print(
            f"[INFO] app_protected.py running (PID {protected_proc.pid}) -> http://localhost:5002"
        )
    try:
        app.run(
            debug=(IS_DEBUG == "1"),
            host="0.0.0.0",
            port=5001,
            use_reloader=False,
            threaded=True,
        )
    finally:
        protected_proc.terminate()
