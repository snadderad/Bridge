import os
import sqlite3
import bcrypt
import secrets
import datetime
import socket
from flask import Flask, request, jsonify, send_from_directory, send_file


app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'Userdata', 'users.db')

# ── Database helpers ──────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with get_db() as db:
        db.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT,
            age INTEGER,
            bio TEXT,
            profile_pic TEXT,
            interests TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )''')

        # Ensure backward compatibility for older DB schema lacking interests column
        existing_columns = [row['name'] for row in db.execute("PRAGMA table_info(users)").fetchall()]
        if 'interests' not in existing_columns:
            db.execute('ALTER TABLE users ADD COLUMN interests TEXT')

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


def query_db(query, args=(), one=False):
    db = get_db()
    cur = db.execute(query, args)
    rv = cur.fetchone() if one else cur.fetchall()
    db.close()
    return rv


# ── Utility helpers ────────────────────────────────────────────────────────────

def is_debug_mode():
    debug_env = os.getenv('DEBUG_MODE', 'False').strip().lower()
    return debug_env in ('1', 'true', 'yes', 'on')


def get_token_from_request():
    return request.headers.get('Authorization') or request.args.get('token')


def get_user_from_token(token):
    # Normal auth path (token based)
    if token:
        row = query_db('SELECT user_id FROM sessions WHERE token = ?', (token,), one=True)
        if row:
            return row['user_id']

    # Debug mode bypass for local dev/testing when no token is provided
    if is_debug_mode():
        # Prefer explicit debug-user id if provided, otherwise first user
        debug_user_id = os.getenv('DEBUG_USER_ID')
        if debug_user_id:
            return int(debug_user_id)

        row = query_db('SELECT id FROM users ORDER BY id LIMIT 1', one=True)
        if row:
            return row['id']

    return None


def unauthorized_response():
    return jsonify({'error': 'Unauthorized'}), 401


@app.errorhandler(Exception)
def handle_exception(e):
    # Log the exception so the service user can debug 500 errors.
    app.logger.exception('Unhandled exception')
    return jsonify({'status': 'error', 'message': 'Internal server error', 'error': str(e)}), 500


# ── Auth routes ───────────────────────────────────────────────────────────────

@app.route('/register', methods=['POST'])
def register():
    if request.is_json:
        data = request.get_json(force=True)
    else:
        # support form submissions from HTML forms (x-www-form-urlencoded/multipart)
        data = request.form.to_dict()

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'status': 'fail', 'message': 'Missing fields'}), 400

    name = data.get('name')
    age = data.get('age')
    bio = data.get('bio')
    profile_pic = data.get('profile_pic')
    interests = data.get('interests')

    print(f"Registering user: {username}, name: {name}, age: {age}, bio: {bio}, profile_pic: {profile_pic}, interests: {interests}")

    # Convert age if provided (make sure it's an int or None)
    if age is not None:
        try:
            age = int(age)
        except (ValueError, TypeError):
            return jsonify({'status': 'fail', 'message': 'Invalid age value'}), 400

    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    try:
        with get_db() as db:
            db.execute(
                'INSERT INTO users (username, password_hash, name, age, bio, profile_pic, interests) VALUES (?, ?, ?, ?, ?, ?, ?)',
                (username, pw_hash, name, age, bio, profile_pic, interests)
            )
            db.commit()
        return jsonify({'status': 'success', 'message': 'User created'})

    except sqlite3.IntegrityError:
        return jsonify({'status': 'fail', 'message': 'Username already exists'}), 409
    except sqlite3.OperationalError as e:
        return jsonify({'status': 'fail', 'message': 'Database error', 'error': str(e)}), 500
    except Exception as e:
        return jsonify({'status': 'fail', 'message': 'Unexpected error', 'error': str(e)}), 500


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'status': 'fail', 'message': 'Missing credentials'}), 400

    user = query_db('SELECT * FROM users WHERE username = ?', (username,), one=True)

    if user and bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
        token = secrets.token_hex(32)

        with get_db() as db:
            db.execute(
                'INSERT INTO sessions (user_id, token, device, logged_in_at) VALUES (?, ?, ?, ?)',
                (user['id'], token, 'unknown', datetime.datetime.now().isoformat())
            )
            db.commit()

        return jsonify({'status': 'success', 'token': token, 'user_id': user['id']})

    return jsonify({'status': 'fail', 'message': 'Invalid credentials'}), 401


# ── Feed routes ────────────────────────────────────────────────────────────────

@app.route('/feed/styles.css')
def feed_styles():
    return send_file('HTML/styles.css')


@app.route('/feed/view')
def feed_view():
    return send_file('HTML/Feed.html')


@app.route('/feed')
def feed():
    token = get_token_from_request()
    user_id = get_user_from_token(token)

    if not user_id:
        return unauthorized_response()

    users = query_db('''
        SELECT u.id, u.name, u.age, u.bio, u.profile_pic
        FROM users u
        WHERE u.id != ?
          AND u.id NOT IN (SELECT target_id FROM connections WHERE user_id = ?)
        ORDER BY RANDOM()
        LIMIT 20
    ''', (user_id, user_id))

    return jsonify([
        {
            'id': row['id'],
            'name': row['name'] or row['id'],
            'age': row['age'] or '',
            'bio': row['bio'] or '',
            'profile_pic': row['profile_pic'] or ''
        } for row in users
    ])



# ── Profile routes ────────────────────────────────────────────────────────────

@app.route('/profile/styles.css')
def profile_styles():
    return send_file('HTML/styles.css')

@app.route('/profile')
def profile():

    token = get_token_from_request()
    user_id = get_user_from_token(token)

    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    db = get_db()
    user = db.execute("SELECT id, name, age, bio, profile_pic, interests FROM users WHERE id = ?", (user_id,)).fetchone()
    db.close()

    if not user:
        return jsonify({'Fatal error': 'User not found'}), 404
    return jsonify(dict(user))



@app.route('/profile/view')
def profile_view():
    return send_file('HTML/profile_view.html')


@app.route('/profile/edit')
def profile_edit():
    return send_file('HTML/profile_edit.html')



@app.route('/profile/update', methods=['POST'])
def profile_update():
    token = request.headers.get('Authorization') or request.args.get('token')
    user_id = get_user_from_token(token)
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    data = None
    if request.is_json:
        data = request.get_json(silent=True)
    if data is None:
        data = request.form.to_dict() if request.form else {}

    if not isinstance(data, dict):
        return jsonify({'status': 'fail', 'message': 'Invalid JSON'}), 400

    age_value = data.get('age')
    if age_value is not None and age_value != '':
        try:
            age_value = int(age_value)
        except (ValueError, TypeError):
            return jsonify({'status': 'fail', 'message': 'Invalid age value'}), 400
    else:
        age_value = None

    db = get_db()
    db.execute("""
        UPDATE users SET name=?, age=?, bio=?, profile_pic=?, interests=? WHERE id=?
    """, (data.get('name'), age_value, data.get('bio'), data.get('profile_pic'), data.get('interests'), user_id))
    db.commit()
    db.close()
    return jsonify({"status": "success"})

# -- dms routes (uncomment when ready) ─────────────────────────────────────────────

@app.route('/chat/styles.css')
def chat_styles():
    return send_file('HTML/styles.css')


@app.route('/chat/view')
def chat_view():
    return send_file('HTML/chat.html')

@app.route('/chat')
def chat():
    token = request.headers.get('Authorization') or request.args.get('token')
    user_id = get_user_from_token(token)
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    try:
        db = get_db()
        chats = db.execute("""
            SELECT u.id as user_id, u.name, u.profile_pic,
                   NULL as last_message, NULL as last_time
            FROM connections c
            JOIN users u ON u.id = c.target_id
            WHERE c.user_id = ?
        """, (user_id,)).fetchall()
        db.close()
        return jsonify([dict(c) for c in chats])
    except Exception as e:
        return jsonify([])





# ── Home (uncomment when ready) ───────────────────────────────────────────────

# @app.route("/")
# def home():
#     return send_from_directory("static", "index.html")


if __name__ == '__main__':
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if s.connect_ex(('localhost', 3000)) == 0:
            print("Port 3000 is already in use. Exiting.")
            exit(1)
    init_db()
    app.run(host='0.0.0.0', port=3000)
