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
    
    Vulnerabilities implemented:
    1. Error-Based SQL Injection - Raw database errors exposed with full details
    2. Stacked Queries - Multiple SQL statements can be executed
    3. Stored Procedure Injection - Dynamic procedure calls vulnerable
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

        # ===================================================================
        # VULNERABILITY 1 & 2: Error-Based + Stacked Queries SQL Injection
        # ===================================================================
        # Build the VULNERABLE login query with string concatenation
        # This allows both error-based extraction and stacked queries
        login_query = (
            f"SELECT * FROM users "
            f"WHERE username = '{raw_username}' AND password = '{raw_password}'"
        )
        executed_query = login_query

        # Execute vulnerable query directly
        try:
            with db_session() as conn:
                if conn is None:
                    auth_status = 'error'
                    sql_error_message = 'Database connection failed.'
                else:
                    # Use cursor that supports multiple statements for stacked queries
                    cursor = conn.cursor(pymysql.cursors.DictCursor)
                    
                    try:
                        if IS_DEBUG == "1":
                            print(f"[SQLI EXEC] {login_query}")
                        
                        # ================================================================
                        # VULNERABILITY 2: STACKED QUERIES SQL INJECTION
                        # ================================================================
                        # Enable multi-statement execution by using executescript or 
                        # executing multiple statements separated by semicolons
                        # PyMySQL doesn't have direct multi=True like mysql-connector,
                        # but we can achieve this by splitting and executing manually
                        
                        # Check if query contains stacked queries (semicolon-separated)
                        if ';' in login_query and login_query.strip().endswith(';'):
                            # Split into multiple statements for stacked query execution
                            statements = [stmt.strip() for stmt in login_query.split(';') if stmt.strip()]
                            
                            first_row = None
                            all_results = []
                            
                            for idx, stmt in enumerate(statements):
                                try:
                                    if IS_DEBUG == "1":
                                        print(f"[STACKED QUERY {idx+1}] {stmt}")
                                    
                                    cursor.execute(stmt)
                                    
                                    # Fetch results if available
                                    if cursor.description:
                                        result_set = cursor.fetchall()
                                        all_results.append({
                                            'statement': stmt,
                                            'rows': result_set,
                                            'columns': [d[0] for d in cursor.description]
                                        })
                                        
                                        # Keep first result for authentication check
                                        if idx == 0 and result_set:
                                            first_row = result_set[0]
                                            query_columns = [d[0] for d in cursor.description]
                                except pymysql.Error as stmt_err:
                                    if IS_DEBUG == "1":
                                        print(f"[STACKED ERROR {idx+1}] {stmt_err}")
                                    # Continue executing remaining statements
                                    pass
                            
                            # Use first result for authentication
                            query_rows = [first_row] if first_row else []
                            
                        else:
                            # ============================================================
                            # VULNERABILITY 3: STORED PROCEDURE INJECTION
                            # ============================================================
                            # Check if input attempts to call stored procedures
                            # This simulates vulnerability where user input can trigger
                            # stored procedure execution with unsanitized parameters
                            
                            # Detect stored procedure calls in input
                            sp_keywords = ['CALL ', 'EXEC ', 'EXECUTE ']
                            is_sp_attempt = any(keyword in raw_username.upper() or keyword in raw_password.upper() 
                                              for keyword in sp_keywords)
                            
                            if is_sp_attempt:
                                if IS_DEBUG == "1":
                                    print("[STORED PROCEDURE] Detected SP attempt")
                                
                                # Attempt to execute as stored procedure call
                                # This is vulnerable because we're executing user input directly
                                try:
                                    # Try to extract and execute stored procedure
                                    # Example payload: admin'; CALL GetUserOrders(1)--
                                    clean_query = login_query.replace('--', '').replace('#', '')
                                    
                                    # Look for CALL statements
                                    if 'CALL' in clean_query.upper():
                                        # Extract and execute the CALL statement
                                        call_start = clean_query.upper().find('CALL')
                                        if call_start != -1:
                                            call_stmt = clean_query[call_start:].split(';')[0].strip()
                                            if IS_DEBUG == "1":
                                                print(f"[SP EXEC] Executing: {call_stmt}")
                                            
                                            # Execute the stored procedure call
                                            cursor.execute(call_stmt)
                                            
                                            # Fetch results from stored procedure
                                            if cursor.description:
                                                sp_results = cursor.fetchall()
                                                query_columns = [d[0] for d in cursor.description]
                                                query_rows = [list(row.values()) for row in sp_results] if sp_results else []
                                                
                                                # If SP returns user data, use it for auth
                                                if sp_results:
                                                    first_row = sp_results[0]
                                                    if isinstance(first_row, dict):
                                                        first_row = list(first_row.values())
                                                    
                                                    if 'username' in query_columns:
                                                        db_username = first_row[query_columns.index('username')]
                                                    elif len(first_row) > 1:
                                                        db_username = first_row[1]
                                                    else:
                                                        db_username = first_row[0]
                                                    
                                                    db_username = str(db_username)
                                                    session['user'] = db_username
                                                    flash(f'Login berhasil via SP! Welcome, {db_username}', 'success')
                                                    return redirect(url_for('home'))
                                except pymysql.Error as sp_err:
                                    if IS_DEBUG == "1":
                                        print(f"[SP ERROR] {sp_err}")
                                    # Fall through to normal query execution
                            
                            # Normal single query execution (still vulnerable to error-based)
                            cursor.execute(login_query)
                            query_columns = [d[0] for d in (cursor.description or [])]
                            first_row = cursor.fetchone()
                            query_rows = [list(first_row.values())] if first_row and isinstance(first_row, dict) else [list(first_row)] if first_row else []
                        
                        conn.commit()

                        # Authentication check (only if not already authenticated via SP)
                        if 'user' not in session and first_row:
                            auth_status = 'success'
                            
                            if isinstance(first_row, dict):
                                if 'username' in first_row:
                                    db_username = first_row['username']
                                elif len(first_row) > 1:
                                    db_username = list(first_row.values())[1]
                                else:
                                    db_username = list(first_row.values())[0]
                            else:
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
                        elif 'user' not in session:
                            auth_status = 'failed'
                            flash('Login gagal: username/password tidak valid.', 'danger')
                            
                    finally:
                        cursor.close()
                        
        except pymysql.Error as exc:
            auth_status = 'error'
            sql_error_message = str(exc)
            if IS_DEBUG == "1":
                print(f"[SQL ERROR] {exc}")

            # =================================================================
            # VULNERABILITY 1: ERROR-BASED SQL INJECTION (IMPROVED)
            # =================================================================
            # Kembalikan raw error database dengan format yang sangat jelas
            # untuk memastikan SQLMap dapat mendeteksi error-based SQL injection
            
            error_code = exc.args[0] if exc.args else 'Unknown'
            error_msg = str(exc)
            
            if IS_DEBUG == "1":
                print(f"[SQLI ERROR-BASED] Code: {error_code}, Message: {error_msg}")
            
            # Format error response yang SANGAT EXPLICIT untuk scanner
            # Include semua informasi debugging yang mungkin dibutuhkan attacker
            error_details = {
                'error_code': error_code,
                'error_message': error_msg,
                'error_type': type(exc).__name__,
                'executed_query': executed_query,
                'input_username': raw_username,
                'input_password': raw_password,
                'mysql_error_number': getattr(exc, 'errno', 'N/A'),
                'mysql_sqlstate': getattr(exc, 'sqlstate', 'N/A')
            }
            
            # Build detailed error response
            error_response_lines = [
                "=" * 80,
                "MYSQL DATABASE ERROR - DEBUG MODE ENABLED",
                "=" * 80,
                f"Error Code: {error_code}",
                f"MySQL Error Number: {error_details['mysql_error_number']}",
                f"MySQL SQLState: {error_details['mysql_sqlstate']}",
                f"Error Type: {error_details['error_type']}",
                "",
                "ERROR MESSAGE:",
                "-" * 80,
                error_msg,
                "",
                "EXECUTED QUERY:",
                "-" * 80,
                executed_query if executed_query else "N/A",
                "",
                "INPUT PARAMETERS:",
                "-" * 80,
                f"Username: {repr(raw_username)}",
                f"Password: {repr(raw_password)}",
                "",
                "STACK TRACE:",
                "-" * 80,
            ]
            
            # Add traceback information
            import traceback
            tb_lines = traceback.format_exc().split('\n')
            error_response_lines.extend(tb_lines[:10])  # First 10 lines of traceback
            
            error_response_lines.append("=" * 80)
            
            error_response = '\n'.join(error_response_lines)
            
            # Return dengan content-type text/plain agar mudah dibaca scanner
            return error_response, 500
            # =================================================================

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