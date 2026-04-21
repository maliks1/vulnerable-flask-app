from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3

app = Flask(__name__)
app.secret_key = 'this is your key'

DB_PATH = 'users.db'


# ── Database helper ────────────────────────────────────────────────────────────

def sql_connect():
    try:
        conn = sqlite3.connect(DB_PATH)
        return conn
    except sqlite3.Error as err:
        print(f"[DB ERROR] {err}")
        return None


# ── SQL statement splitter (respects single-quoted strings) ───────────────────

def parse_statements(raw_sql):
    """
    Split a raw SQL string into individual statements on ';',
    while correctly handling single-quoted string literals
    (including SQL-escaped '' quotes inside strings).

    Example:
        "SELECT * FROM users; DROP TABLE users"
        → ["SELECT * FROM users", "DROP TABLE users"]

        "SELECT * FROM users WHERE name='O''Brien'; SELECT 1"
        → ["SELECT * FROM users WHERE name='O''Brien'", "SELECT 1"]
    """
    statements = []
    buf = []
    in_str = False
    i = 0

    while i < len(raw_sql):
        ch = raw_sql[i]

        if in_str:
            buf.append(ch)
            if ch == "'":
                # escaped quote '' → stay inside the string
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

    # Trailing statement without a semicolon
    tail = "".join(buf).strip()
    if tail:
        statements.append(tail)

    return statements


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route('/home')
def home():
    if 'user' not in session:
        flash('Silakan login terlebih dahulu.', 'warning')
        return redirect(url_for('login'))
    return (
        f"<h2>Welcome, {session['user']}!</h2>"
        f"<a href='{url_for('login')}'>Logout</a>"
    )


@app.route('/', methods=['GET', 'POST'])
def login():
    """
    INTENTIONALLY VULNERABLE login endpoint.

    The username and password are injected into a pre-built SQL query
    via Python f-string (no parameterization, no escaping), making it
    vulnerable to every classic SQL injection technique:

      Technique            | Example payload (in username field)
      ---------------------|----------------------------------------------------
      Classic bypass       | ' OR '1'='1' --
      Comment bypass       | admin' --
      Union-based          | ' UNION SELECT 1,username,password FROM users --
      Error-based          | ' AND 1=CAST('x' AS INTEGER) --
      Boolean blind        | ' AND substr(password,1,1)='a' --
      Time-based blind     | ' AND 1=(SELECT CASE WHEN (1=1)
                           |   THEN randomblob(100000000) ELSE 0 END) --
      Stacked queries      | '; INSERT INTO users VALUES(99,'hacker','pwned') --
      Schema enumeration   | ' UNION SELECT name,sql FROM sqlite_master --
    """
    executed_query = None
    query_results  = []      # list[dict] – one entry per executed statement
    login_bypass   = False
    raw_username   = ''
    raw_password   = ''

    if request.method == 'POST':
        raw_username = request.form.get('username', '')
        raw_password = request.form.get('password', '')

        # ── Build the VULNERABLE login query ────────────────────────────────
        # Intentionally uses f-string concatenation instead of ? placeholders.
        # This is the root cause of ALL injection vulnerabilities below.
        login_query = (
            f"SELECT * FROM users "
            f"WHERE username = '{raw_username}' AND password = '{raw_password}'"
        )
        executed_query = login_query

        # ── Execute every statement (stacked query support) ──────────────────
        conn = sql_connect()
        if conn is None:
            flash('Database connection failed.', 'danger')
        else:
            cursor = conn.cursor()
            try:
                for stmt in parse_statements(login_query):
                    entry = {
                        'stmt':     stmt,
                        'columns':  [],
                        'rows':     [],
                        'rowcount': None,
                        'error':    None,
                    }

                    try:
                        print(f"[SQLI EXEC] {stmt}")
                        cursor.execute(stmt)

                        if cursor.description:
                            # Result-returning statement (SELECT, PRAGMA, …)
                            entry['columns'] = [d[0] for d in cursor.description]
                            entry['rows']    = [list(r) for r in cursor.fetchall()]
                        else:
                            # DML / DDL – commit and record affected rows
                            conn.commit()
                            entry['rowcount'] = cursor.rowcount

                    except sqlite3.Error as exc:
                        # !! Error message is exposed verbatim → error-based SQLi
                        entry['error'] = str(exc)
                        print(f"[SQL ERROR] {exc}")

                    query_results.append(entry)

            finally:
                cursor.close()
                conn.close()

        # ── Determine login outcome ──────────────────────────────────────────

        # 1. Legitimate login (hard-coded check)
        if raw_username == 'admin' and raw_password == 'admin123':
            session['user'] = 'admin'
            flash('Login berhasil!', 'success')
            return redirect(url_for('home'))

        # 2. SQLi bypass – the injected SELECT returned at least one row
        first_select = next(
            (e for e in query_results if e['columns'] and not e['error']),
            None
        )
        if first_select and first_select['rows']:
            login_bypass = True

    return render_template(
        'login.html',
        executed_query = executed_query,
        query_results  = query_results,
        login_bypass   = login_bypass,
        raw_username   = raw_username,
        raw_password   = raw_password,
    )


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    # debug=True → full Flask tracebacks in browser (extra info leakage)
    app.run(debug=True, host='0.0.0.0', port=5001)
