from flask import Flask, render_template, request, redirect, url_for, flash, session
import pymysql
import pymysql.constants.CLIENT
import subprocess
import sys
import os
import traceback
from contextlib import contextmanager

# Unified Configuration (from config.py)
IS_DEBUG = os.environ.get("IS_DEBUG", "1")

# Unified Database Configuration (from mysql_config.py)
MYSQL_CONFIG = {
    'host': '127.0.0.1',
    'port': 3306,
    'user': 'root',
    'password': '',
    'database': 'users'
}

# Unified Database Session (from utils.py)
def sql_connect() -> pymysql.connections.Connection | None:
    try:
        return pymysql.connect(
            host=MYSQL_CONFIG['host'],
            port=MYSQL_CONFIG['port'],
            user=MYSQL_CONFIG['user'],
            password=MYSQL_CONFIG['password'],
            database=MYSQL_CONFIG['database'],
            client_flag=pymysql.constants.CLIENT.MULTI_STATEMENTS
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
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'this-is-a-fallback-vulnerable-key-2024')

@app.route('/home')
def home():
    if 'user' not in session:
        flash('Silakan login terlebih dahulu.', 'warning')
        return redirect(url_for('login'))
    return render_template('vulnerable_home.html', username=session['user'])

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash('Anda telah logout.', 'info')
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
def login():
    executed_query = None
    auth_status = 'idle'
    db_username = None
    sql_error_message = None
    query_columns, query_rows = [], []
    raw_username, raw_password = '', ''

    if request.method == 'POST':
        raw_username = request.form.get('username', '')
        raw_password = request.form.get('password', '')
        login_query = f"SELECT * FROM users WHERE username = '{raw_username}' AND password = '{raw_password}'"
        executed_query = login_query

        try:
            with db_session() as conn:
                if conn is None:
                    auth_status = 'error'
                    sql_error_message = 'Database connection failed.'
                else:
                    with conn.cursor(pymysql.cursors.DictCursor) as cursor:
                        if IS_DEBUG == "1":
                            print(f"[SQLI EXEC] {login_query}")

                        first_row = None

                        # VULN: Stacked queries
                        if ';' in login_query and login_query.strip().endswith(';'):
                            stmts = [s.strip() for s in login_query.split(';') if s.strip()]
                            for idx, stmt in enumerate(stmts):
                                try:
                                    cursor.execute(stmt)
                                    if cursor.description:
                                        rs = cursor.fetchall()
                                        if idx == 0 and rs:
                                            first_row = rs[0]
                                            query_columns = [d[0] for d in cursor.description]
                                except pymysql.Error:
                                    pass
                            query_rows = [first_row] if first_row else []
                        else:
                            # VULN: Stored procedure injection
                            sp_kw = ['CALL ', 'EXEC ', 'EXECUTE ']
                            is_sp = any(k in raw_username.upper() or k in raw_password.upper() for k in sp_kw)
                            if is_sp:
                                if IS_DEBUG == "1":
                                    print("[STORED PROCEDURE] Detected SP attempt")
                                clean = login_query.replace('--', '').replace('#', '')
                                if 'CALL' in clean.upper():
                                    cs = clean.upper().find('CALL')
                                    call_stmt = clean[cs:].split(';')[0].strip()
                                    cursor.execute(call_stmt)
                                    if cursor.description:
                                        sp_rs = cursor.fetchall()
                                        query_columns = [d[0] for d in cursor.description]
                                        query_rows = [list(r.values()) for r in sp_rs] if sp_rs else []
                                        if sp_rs:
                                            r0 = sp_rs[0]
                                            rv = list(r0.values()) if isinstance(r0, dict) else list(r0)
                                            db_username = str(rv[query_columns.index('username')] if 'username' in query_columns else (rv[1] if len(rv) > 1 else rv[0]))
                                            session['user'] = db_username
                                            flash(f'Login berhasil via SP! Welcome, {db_username}', 'success')
                                            return redirect(url_for('home'))

                            cursor.execute(login_query)
                            query_columns = [d[0] for d in (cursor.description or [])]
                            first_row = cursor.fetchone()
                            query_rows = [list(first_row.values())] if first_row and isinstance(first_row, dict) else [list(first_row)] if first_row else []

                        conn.commit()

                        if 'user' not in session and first_row:
                            auth_status = 'success'
                            if isinstance(first_row, dict):
                                db_username = first_row.get('username') or (list(first_row.values())[1] if len(first_row) > 1 else list(first_row.values())[0])
                            else:
                                db_username = first_row[query_columns.index('username')] if 'username' in query_columns else (first_row[1] if len(first_row) > 1 else first_row[0])
                            db_username = str(db_username)
                            session['user'] = db_username
                            flash(f'Login berhasil! Welcome, {db_username}', 'success')
                            return redirect(url_for('home'))
                        elif 'user' not in session:
                            auth_status = 'failed'
                            flash('Login gagal: username/password tidak valid.', 'danger')

        except pymysql.Error as exc:
            auth_status = 'error'
            sql_error_message = str(exc)
            if IS_DEBUG == "1":
                print(f"[SQL ERROR] {exc}")

            # VULN: Error-based SQL injection - return raw DB error details
            error_parts = [
                "=" * 80,
                "MYSQL DATABASE ERROR - DEBUG MODE ENABLED",
                "=" * 80,
                f"Error Code: {exc.args[0] if exc.args else 'Unknown'}",
                f"MySQL Error Number: {getattr(exc, 'errno', 'N/A')}",
                f"MySQL SQLState: {getattr(exc, 'sqlstate', 'N/A')}",
                f"Error Type: {type(exc).__name__}",
                "",
                "ERROR MESSAGE:",
                "-" * 80,
                str(exc),
                "",
                "EXECUTED QUERY:",
                "-" * 80,
                executed_query or "N/A",
                "",
                "INPUT PARAMETERS:",
                "-" * 80,
                f"Username: {repr(raw_username)}",
                f"Password: {repr(raw_password)}",
                "",
                "STACK TRACE:",
                "-" * 80,
            ]
            error_parts.extend(traceback.format_exc().split('\n')[:10])
            error_parts.append("=" * 80)
            return '\n'.join(error_parts), 500

    return render_template('login.html',
        executed_query=executed_query,
        auth_status=auth_status,
        db_username=db_username,
        sql_error_message=sql_error_message,
        query_columns=query_columns,
        query_rows=query_rows,
        raw_username=raw_username,
        raw_password=raw_password,
    )

if __name__ == '__main__':
    protected_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'app_protected.py')
    protected_proc = subprocess.Popen([sys.executable, protected_script])
    if IS_DEBUG == "1":
        print(f"[INFO] app_protected.py running (PID {protected_proc.pid}) -> http://localhost:5002")
    try:
        app.run(debug=(IS_DEBUG == "1"), host='0.0.0.0', port=5001, use_reloader=False)
    finally:
        protected_proc.terminate()
        if IS_DEBUG == "1":
            print("[INFO] app_protected.py stopped.")
