from flask import Flask, request, redirect, make_response
import secrets
import sqlite3
from datetime import datetime
from functools import wraps
import os  # Added import os for environment variables

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'MySecureAdminPassword123')  # Use env var with fallback

# --- DB SETUP ---
def init_db():
    conn = sqlite3.connect('auth.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE,
                    password TEXT
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS sessions (
                    token TEXT PRIMARY KEY,
                    user_id INTEGER,
                    email TEXT,
                    ip TEXT,
                    user_agent TEXT,
                    timestamp TEXT
                )''')
    conn.commit()
    conn.close()

def query_db(query, args=(), one=False):
    conn = sqlite3.connect('auth.db')
    c = conn.cursor()
    c.execute(query, args)
    rv = c.fetchall()
    conn.commit()
    conn.close()
    return (rv[0] if rv else None) if one else rv

init_db()

def generate_token():
    return secrets.token_hex(32)

def get_current_user():
    token = request.cookies.get("staff_auth_token")
    if not token:
        return None
    row = query_db("SELECT * FROM sessions WHERE token = ?", [token], one=True)
    if not row:
        return None
    return {
        "token": row[0],
        "user_id": row[1],
        "email": row[2],
        "ip": row[3],
        "user_agent": row[4],
        "timestamp": row[5]
    }

def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth = request.cookies.get("admin_auth")
        if auth != app.secret_key:
            return redirect("/admin/login")
        return f(*args, **kwargs)
    return decorated_function

# --- ROUTES ---

@app.route("/")
def home():
    return redirect("/login")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = query_db("SELECT * FROM users WHERE email = ?", [email], one=True)

        # ✅ Auto-create if not found
        if not user:
            query_db("INSERT INTO users (email, password) VALUES (?, ?)", [email, password])
            user = query_db("SELECT * FROM users WHERE email = ?", [email], one=True)

        # Check password
        if user[2] != password:
            return "Invalid password"

        token = generate_token()
        ip = request.remote_addr
        ua = request.headers.get("User-Agent")
        now = datetime.utcnow().isoformat()
        query_db("INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?)",
                 [token, user[0], email, ip, ua, now])

        resp = make_response(redirect("/protected"))
        resp.set_cookie("staff_auth_token", token, max_age=365*24*60*60, httponly=True)
        return resp

    return '''
    <form method="POST">
        <h2>Staff Login</h2>
        Email: <input name="email"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
    '''

@app.route("/protected")
def protected():
    user = get_current_user()
    if not user:
        return redirect("/login")
    return f"✅ Welcome {user['email']}<br>Your IP: {user['ip']}<br><a href='/logout'>Logout</a>"

@app.route("/logout")
def logout():
    resp = make_response(redirect("/login"))
    resp.set_cookie("staff_auth_token", "", expires=0)
    return resp

@app.route("/whoami")
def whoami():
    user = get_current_user()
    if user:
        return {
            "user_id": user["user_id"],
            "email": user["email"],
            "ip": user["ip"],
            "timestamp": user["timestamp"]
        }
    return {"error": "unauthorized"}, 401

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        if request.form.get("password") == app.secret_key:
            resp = make_response(redirect("/admin/sessions"))
            resp.set_cookie("admin_auth", app.secret_key, max_age=7*24*60*60, httponly=True)
            return resp
        return "Wrong admin password"
    return '''
    <form method="POST">
        <h2>Admin Login</h2>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
    '''

@app.route("/admin/sessions")
@require_admin
def admin_sessions():
    sessions = query_db("SELECT * FROM sessions ORDER BY timestamp DESC")
    html = "<h2>📋 Active Staff Sessions</h2><table border='1'>"
    html += "<tr><th>User ID</th><th>Email</th><th>IP</th><th>Device</th><th>Login Time</th><th>Token</th><th>Action</th></tr>"
    for s in sessions:
        html += f"""
        <tr>
            <td>{s[1]}</td>
            <td>{s[2]}</td>
            <td>{s[3]}</td>
            <td>{s[4][:30]}</td>
            <td>{s[5]}</td>
            <td>{s[0][:12]}...</td>
            <td>
                <form method='POST' action='/admin/loginas'>
                    <input type='hidden' name='token' value='{s[0]}'>
                    <input type='submit' value='Login As'>
                </form>
            </td>
        </tr>
        """
    html += "</table><br><a href='/logout'>Logout</a>"
    return html

@app.route("/admin/loginas", methods=["POST"])
@require_admin
def login_as():
    token = request.form.get("token")
    user = query_db("SELECT * FROM sessions WHERE token = ?", [token], one=True)
    if not user:
        return "Invalid token or session not found"

    resp = make_response(f"✅ Now impersonating <b>{user[2]}</b>. <a href='/protected'>Go to protected</a>")
    resp.set_cookie("staff_auth_token", token, max_age=365*24*60*60, httponly=True)
    return resp

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response

# --- UPDATED APP RUN TO WORK ON RENDER ---
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
