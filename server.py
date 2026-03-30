from flask import Flask, request, jsonify, send_from_directory, send_file
import sqlite3, bcrypt, secrets, datetime

app = Flask(__name__)
DB = 'users.db'

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT,
            age INTEGER,
            bio TEXT,
            profile_pic TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )''')
        db.execute('''CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            device TEXT,
            logged_in_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )''')
        db.execute('''CREATE TABLE IF NOT EXISTS connections (
            user_id INTEGER NOT NULL,
            target_id INTEGER NOT NULL,
            PRIMARY KEY (user_id, target_id)
        )''')
        db.commit()

init_db()


def get_user_from_token(token):
    """Returns user_id if token is valid, else None."""
    if not token:
        return None
    db = get_db()
    row = db.execute("SELECT user_id FROM sessions WHERE token = ?", (token,)).fetchone()
    db.close()
    return row["user_id"] if row else None


# ── Auth ──────────────────────────────────────────────────────────────────────

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json(force=True)
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        print("Missing fields in registration")
        return jsonify({'status': 'fail', 'message': 'Missing fields'})

    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    try:
        with get_db() as db:
            db.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, pw_hash))
            db.commit()
            print(f"User {username} registered successfully")
        return jsonify({'status': 'success', 'message': 'User created'})

    except sqlite3.IntegrityError:
        print(f"Username {username} already exists")
        return jsonify({'status': 'fail', 'message': 'Username already exists'})


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json(force=True)
    username = data.get('username')
    password = data.get('password')

    with get_db() as db:
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user and bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
            token = secrets.token_hex(32)
            db.execute(
                'INSERT INTO sessions (user_id, token, device, logged_in_at) VALUES (?, ?, ?, ?)',
                (user['id'], token, 'unknown', datetime.datetime.now().isoformat())
            )
            db.commit()
            return jsonify({
                'status': 'success',
                'token': token,
                'user_id': user['id']
            })
        else:
            return jsonify({'status': 'fail', 'message': 'Invalid credentials'})


# ── Feed ──────────────────────────────────────────────────────────────────────


@app.route('/feed/styles.css')
def feed_styles():
    return send_file('Feed/styles.css')

@app.route('/feed/view')
def feed_view():
    print("Feed view route hit")
    return send_file('Feed/Feed.html')


@app.route('/feed')
def feed():
    print("Feed API route hit")
    token = request.headers.get('Authorization') or request.args.get('token')
    user_id = get_user_from_token(token)

    if not user_id:
        print("Unauthorized access attempt")

        return jsonify({"error": "Unauthorized"}), 401

    db = get_db()
    users = db.execute("""
        SELECT u.id, u.name, u.age, u.bio, u.profile_pic
        FROM users u
        WHERE u.id != ?
        AND u.id NOT IN (
            SELECT target_id FROM connections WHERE user_id = ?
        )
        ORDER BY RANDOM()
        LIMIT 20
    """, (user_id, user_id)).fetchall()
    db.close()

    return jsonify([{
        "id":          row["id"],
        "name":        row["name"] or row["id"],
        "age":         row["age"] or "",
        "bio":         row["bio"] or "",
        "profile_pic": row["profile_pic"] or ""
    } for row in users])


@app.route('/connect', methods=['POST'])
def connect():
    print("Connect route hit")
    token = request.headers.get('Authorization') or request.args.get('token')
    user_id = get_user_from_token(token)

    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(force=True)
    target_id = data.get("target_id")

    if not target_id or target_id == user_id:
        return jsonify({"error": "Invalid target"}), 400

    db = get_db()
    try:
        db.execute(
            "INSERT OR IGNORE INTO connections (user_id, target_id) VALUES (?, ?)",
            (user_id, target_id)
        )
        db.commit()
    finally:
        db.close()

    return jsonify({"status": "connected"})

@app.route('/profile')
def profile():
    print("Profile route hit")
    token = request.headers.get('Authorization') or request.args.get('token')
    user_id = get_user_from_token(token)

    if not user_id:
        print("Unauthorized access attempt to profile")
        
        return jsonify({"error": "Unauthorized"}), 401

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    db.close()

    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "id": user["id"],
        "name": user["name"],
        "age": user["age"],
        "bio": user["bio"],
        "profile_pic": user["profile_pic"]
    })


# ── Home (uncomment when ready) ───────────────────────────────────────────────

# @app.route("/")
# def home():
#     print("Home route hit")
#     try:
#         return send_from_directory("static", "index.html")
#     except Exception as e:
#         print(f"Error: {e}")
#         return str(e), 500


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=3000)