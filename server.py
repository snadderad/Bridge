import os
import sqlite3
import bcrypt
import secrets
import datetime
from flask import Flask, request, jsonify, send_from_directory, send_file

app = Flask(__name__)
DB_PATH = 'Userdata/users.db'

# ── Database helpers ──────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
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


def query_db(query, args=(), one=False):
    db = get_db()
    cur = db.execute(query, args)
    rv = cur.fetchone() if one else cur.fetchall()
    db.close()
    return rv


# ── Utility helpers ────────────────────────────────────────────────────────────

def get_token_from_request():
    return request.headers.get('Authorization') or request.args.get('token')


def get_user_from_token(token):
    if not token:
        return None
    row = query_db('SELECT user_id FROM sessions WHERE token = ?', (token,), one=True)
    return row['user_id'] if row else None


def unauthorized_response():
    return jsonify({'error': 'Unauthorized'}), 401


# ── Auth routes ───────────────────────────────────────────────────────────────

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json(force=True)
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'status': 'fail', 'message': 'Missing fields'}), 400

    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    try:
        with get_db() as db:
            db.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, pw_hash))
            db.commit()
        return jsonify({'status': 'success', 'message': 'User created'})

    except sqlite3.IntegrityError:
        return jsonify({'status': 'fail', 'message': 'Username already exists'}), 409


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json(force=True)
    username = data.get('username')
    password = data.get('password')

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
    data = request.get_json(force=True)
    db = get_db()
    db.execute("""
        UPDATE users SET name=?, age=?, bio=?, profile_pic=?, interests=? WHERE id=?
    """, (data.get('name'), data.get('age'), data.get('bio'), data.get('profile_pic'), data.get('interests'), user_id))
    db.commit()
    db.close()
    return jsonify({"status": "success"})






# ── Home (uncomment when ready) ───────────────────────────────────────────────

# @app.route("/")
# def home():
#     return send_from_directory("static", "index.html")


if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=port)
