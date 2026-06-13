import os
import subprocess
import sys
import traceback
from contextlib import contextmanager

import pymysql
import pymysql.constants.CLIENT
from flask import Flask, flash, redirect, render_template, request, session, url_for

# Unified Configuration (from config.py)
IS_DEBUG = os.environ.get("IS_DEBUG", "1")

# Unified Database Configuration (from mysql_config.py)
MYSQL_CONFIG = {
    "host": "127.0.0.1",
    "port": 3306,
    "user": "root",
    "password": "",
    "database": "users",
}


# Unified Database Session (from utils.py)
def sql_connect() -> pymysql.connections.Connection | None:
    try:
        return pymysql.connect(
            host=MYSQL_CONFIG["host"],
            port=MYSQL_CONFIG["port"],
            user=MYSQL_CONFIG["user"],
            password=MYSQL_CONFIG["password"],
            database=MYSQL_CONFIG["database"],
            client_flag=pymysql.constants.CLIENT.MULTI_STATEMENTS,
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
app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY", "this-is-a-fallback-vulnerable-key-2024"
)


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
    executed_query = None
    auth_status = "idle"
    db_username = None
    sql_error_message = None
    query_columns, query_rows = [], []
    raw_username, raw_password = "", ""

    if request.method == "POST":
        raw_username = request.form.get("username", "")
        raw_password = request.form.get("password", "")
        login_query = f"SELECT * FROM users WHERE username = '{raw_username}' AND password = '{raw_password}'"
        executed_query = login_query

        try:
            with db_session() as conn:
                if conn is None:
                    auth_status = "error"
                    sql_error_message = "Database connection failed."
                else:
                    with conn.cursor(pymysql.cursors.DictCursor) as cursor:
                        if IS_DEBUG == "1":
                            print(f"[SQLI EXEC] {login_query}")

                        first_row = None

                        # VULN: Stored procedure injection
                        sp_kw = ["CALL ", "EXEC ", "EXECUTE "]
                        is_sp = any(
                            k in raw_username.upper() or k in raw_password.upper()
                            for k in sp_kw
                        )
                        if is_sp:
                            if IS_DEBUG == "1":
                                print("[STORED PROCEDURE] Detected SP attempt")
                            clean = login_query.replace("--", "").replace("#", "")
                            if "CALL" in clean.upper():
                                cs = clean.upper().find("CALL")
                                # FIX: Bersihkan sisa potongan SQL agar tidak Syntax Error
                                call_stmt = clean[cs:].split(";")[0].split("'")[0].strip()
                                try:
                                    cursor.execute(call_stmt)
                                    if cursor.description:
                                        sp_rs = cursor.fetchall()
                                        query_columns = [
                                            d[0] for d in cursor.description
                                        ]
                                        query_rows = (
                                            [list(r.values()) for r in sp_rs]
                                            if sp_rs
                                            else []
                                        )
                                        if sp_rs:
                                            r0 = sp_rs[0]
                                            rv = (
                                                list(r0.values())
                                                if isinstance(r0, dict)
                                                else list(r0)
                                            )
                                            db_username = str(
                                                rv[query_columns.index("username")]
                                                if "username" in query_columns
                                                else (rv[1] if len(rv) > 1 else rv[0])
                                            )
                                            session["user"] = db_username
                                            flash(
                                                f"Login berhasil via SP! Welcome, {db_username}",
                                                "success",
                                            )
                                            return redirect(url_for("home"))
                                except pymysql.Error:
                                    # FIX: Tangani error SP secara lokal agar tidak membatalkan request
                                    pass 

                        # FIX: Eksekusi Native untuk Stacked Queries & Time-Based
                        # Mengganti split(";") manual dengan nextset() agar sqlmap melihat hasil query kedua
                        cursor.execute(login_query)
                        
                        if cursor.description:
                            rs = cursor.fetchall()
                            if rs:
                                first_row = rs[0]
                                query_columns = [d[0] for d in cursor.description]
                        
                        # Ambil hasil query stacked (jika ada)
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
                            return redirect(url_for("home"))
                        elif "user" not in session:
                            auth_status = "failed"
                            flash(
                                "Login gagal: username/password tidak valid.", "danger"
                            )

        except pymysql.Error as exc:
            auth_status = "error"
            sql_error_message = str(exc)
            
            # FIX: Memastikan pesan error muncul di HTTP Response agar terdeteksi sqlmap (Illegal_Query)
            executed_query = f"{executed_query} -- [SQL ERROR] {sql_error_message}"
            flash(f"Database Error: {sql_error_message}", "danger")
            
            if IS_DEBUG == "1":
                print(f"[SQL ERROR] {exc}")

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
        if IS_DEBUG == "1":
            print("[INFO] app_protected.py stopped.")