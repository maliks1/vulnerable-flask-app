from flask import Flask, render_template, request, redirect, url_for, flash, session
import pymysql
import subprocess
import sys
import os
from config import IS_DEBUG

# Import helper functions from centralized utils module
from utils import db_session

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'this-is-a-fallback-vulnerable-key-2024')

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route('/home')
def home():
    if 'user' not in session:
        flash('Silakan login terlebih dahulu.', 'warning')
        return redirect(url_for('login'))
    username = session['user']
    return render_template('vulnerable_home.html', username=username)

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash('Anda telah logout.', 'info')
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
def login():
    """
    INTENTIONALLY VULNERABLE login endpoint.
    Handles 10 SQLi vulnerabilities using native string interpolation:
    1. Error-Based
    2. Illegal Query
    3. Union-Based
    4. Tautology
    5. Stored Procedure
    6. End-of-Line Comment
    7. Inline Comments
    8. Stacked Queries
    9. Time-Based Blind
    10. Boolean-Based Blind
    """
    executed_query     = None
    auth_status        = 'idle'
    db_username        = None
    sql_error_message  = None
    query_columns      = []
    query_rows         = []
    raw_username       = ''
    raw_password       = ''

    if request.method == 'POST':
        raw_username = request.form.get('username', '')
        raw_password = request.form.get('password', '')

        # Direct string interpolation - fully vulnerable
        login_query = (
            f"SELECT * FROM users "
            f"WHERE username = '{raw_username}' AND password = '{raw_password}'"
        )
        executed_query = login_query

        try:
            with db_session() as conn:
                if conn is None:
                    auth_status = 'error'
                    sql_error_message = 'Database connection failed.'
                    return render_template(
                        'login.html',
                        executed_query    = executed_query,
                        auth_status       = 'error',
                        sql_error_message = sql_error_message,
                        raw_username      = raw_username,
                        raw_password      = raw_password,
                        query_columns     = [],
                        query_rows        = []
                    ), 500

                cursor = conn.cursor(pymysql.cursors.DictCursor)

                try:
                    if IS_DEBUG == "1":
                        print(f"[SQLI EXEC] {login_query}")

                    # Execute query directly (supports stacked queries natively via MULTI_STATEMENTS flag)
                    cursor.execute(login_query)

                    # Retrieve first result set
                    if cursor.description:
                        query_columns = [d[0] for d in cursor.description]
                        first_results = cursor.fetchall()
                        query_rows = [list(r.values()) for r in first_results] if first_results else []

                    # Retrieve subsequent result sets (stacked queries, stored procedures)
                    while cursor.nextset():
                        if cursor.description:
                            next_columns = [d[0] for d in cursor.description]
                            next_results = cursor.fetchall()
                            if next_results:
                                if not query_columns:
                                    query_columns = next_columns
                                query_rows.extend([list(r.values()) for r in next_results])

                    conn.commit()

                    # Check authorization and set session if success
                    if query_rows:
                        auth_status = 'success'
                        first_row = query_rows[0]
                        # Assume username is the second field in the users table schema, fallback to first
                        db_username = first_row[1] if len(first_row) > 1 else first_row[0]
                        session['user'] = str(db_username)
                    else:
                        auth_status = 'failed'

                    # Return 200 with result rows for SQLmap analysis
                    return render_template(
                        'login.html',
                        executed_query    = executed_query,
                        auth_status       = auth_status,
                        db_username       = str(db_username) if db_username else None,
                        sql_error_message = None,
                        query_columns     = query_columns,
                        query_rows        = query_rows,
                        raw_username      = raw_username,
                        raw_password      = raw_password,
                    ), 200

                except pymysql.Error as exc:
                    if IS_DEBUG == "1":
                        print(f"[SQLI ERROR] {exc}")
                    return render_template(
                        'login.html',
                        executed_query    = executed_query,
                        auth_status       = 'error',
                        sql_error_message = str(exc),
                        raw_username      = raw_username,
                        raw_password      = raw_password,
                        query_columns     = [],
                        query_rows        = []
                    ), 500
                finally:
                    try:
                        cursor.close()
                    except Exception:
                        pass

        except pymysql.Error as exc:
            if IS_DEBUG == "1":
                print(f"[SQLI CONNECTION ERROR] {exc}")
            return render_template(
                'login.html',
                executed_query    = executed_query,
                auth_status       = 'error',
                sql_error_message = str(exc),
                raw_username      = raw_username,
                raw_password      = raw_password,
                query_columns     = [],
                query_rows        = []
            ), 500

    return render_template(
        'login.html',
        executed_query    = executed_query,
        auth_status       = auth_status,
        db_username       = db_username,
        sql_error_message = sql_error_message,
        query_columns     = query_columns,
        query_rows        = query_rows,
        raw_username      = raw_username,
        raw_password      = raw_password,
    )

# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    # Auto-launch app_protected.py in the background (port 5002)
    protected_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'app_protected.py')
    protected_proc = subprocess.Popen(
        [sys.executable, protected_script],
    )
    if IS_DEBUG == "1":
        print(f"[INFO] app_protected.py berjalan (PID {protected_proc.pid}) -> http://localhost:5002")

    try:
        app.run(debug=(IS_DEBUG == "1"), host='0.0.0.0', port=5001, use_reloader=False, threaded=True)
    finally:
        protected_proc.terminate()
        if IS_DEBUG == "1":
            print("[INFO] app_protected.py dihentikan.")
