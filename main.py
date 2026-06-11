from flask import Flask, render_template, request, redirect, url_for, flash, session
import pymysql
import subprocess
import sys
import os
from config import IS_DEBUG

# Import helper functions from centralized utils module
from utils import sql_connect, parse_statements, db_session

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

        # Build the VULNERABLE login query
        login_query = (
            f"SELECT * FROM users "
            f"WHERE username = '{raw_username}' AND password = '{raw_password}'"
        )
        executed_query = login_query

        # Execute vulnerable query directly (single execute path)
        try:
            with db_session() as conn:
                if conn is None:
                    auth_status = 'error'
                    sql_error_message = 'Database connection failed.'
                else:
                    cursor = conn.cursor()
                    try:
                        if IS_DEBUG == "1":
                            print(f"[SQLI EXEC] {login_query}")
                        cursor.execute(login_query)
                        query_columns = [d[0] for d in (cursor.description or [])]
                        first_row = cursor.fetchone()

                        # === FULLY VULNERABLE TO STACKED QUERIES & STORED PROCEDURES ===
                        # Remove draining logic to allow all stacked queries and stored procedures to execute
                        # Execute all statements in the query (including stacked queries and stored procedures)
                        try:
                            while True:
                                # Fetch next result set (for stacked queries and stored procedures)
                                if not cursor.nextset():
                                    break
                                # Fetch any results from the additional statements to prevent errors
                                try:
                                    cursor.fetchall()
                                except:
                                    pass  # Ignore errors from statements without result sets
                        except pymysql.Error:
                            # Ignore "no more result sets" errors - this is expected for stacked queries
                            pass

                        conn.commit()  # Commit all statements without draining
                        # ==============================================================

                        if first_row:
                            auth_status = 'success'
                            query_rows = [list(first_row)]

                            if 'username' in query_columns:
                                db_username = first_row[query_columns.index('username')]
                            elif len(first_row) > 1:
                                db_username = first_row[1]
                            else:
                                db_username = first_row[0]

                            db_username = str(db_username)
                            session['user'] = db_username
                            flash(f'Login berhasil! Welcome, {db_username}', 'success')
                            return redirect(url_for('home'))
                        else:
                            auth_status = 'failed'
                            flash('Login gagal: username/password tidak valid.', 'danger')
                    finally:
                        cursor.close()
        except pymysql.Error as exc:
            auth_status = 'error'
            sql_error_message = str(exc)
            if IS_DEBUG == "1":
                print(f"[SQL ERROR] {exc}")

            # === ERROR-BASED SQLi VULNERABILITY ===
            # Kembalikan raw error database untuk memastikan SQLMap
            # dapat mendeteksi error-based SQL injection
            error_msg = str(exc)
            if IS_DEBUG == "1":
                print(f"[SQLI ERROR-BASED] {error_msg}")
            # Format error yang jelas dan mudah dideteksi scanner
            return f"Database Error: {error_msg}", 500
            # ====================================

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
        app.run(debug=(IS_DEBUG == "1"), host='0.0.0.0', port=5001, use_reloader=False)
    finally:
        # Ensure the subprocess dies when main.py stops
        protected_proc.terminate()
        if IS_DEBUG == "1":
            print("[INFO] app_protected.py dihentikan.")