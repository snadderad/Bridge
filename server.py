from flask import Flask, request, jsonify, send_from_directory
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
        db.commit()

init_db()


@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return jsonify({'status': 'fail', 'message': 'Missing fields'})

    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    try:
        with get_db() as db:
            db.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, pw_hash))
            db.commit()
        return jsonify({'status': 'success', 'message': 'User created'})
    except sqlite3.IntegrityError:
        return jsonify({'status': 'fail', 'message': 'Username already exists'})


#Login Post server
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    device = request.form.get('device', 'unknown')  # send device name from App Inventor

    with get_db() as db:
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user and bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
            token = secrets.token_hex(32)
            db.execute(
                'INSERT INTO sessions (user_id, token, device, logged_in_at) VALUES (?, ?, ?, ?)',
                (user['id'], token, device, datetime.datetime.now().isoformat())
            )
            db.commit()
            return jsonify({
                'status': 'success',
                'token': token,
                'user_id': user['id']
            })
        else:
            return jsonify({'status': 'fail', 'message': 'Invalid credentials'})
        


#Home Website page
@app.route("/")
def home():
    print("Home route hit")
    try:
        return send_from_directory("C:\\Users\\sande\\Code\\Bridge\\static", "index.html")
    except Exception as e:
        print(f"Error: {e}")
        return str(e), 500
>>>>>>> Stashed changes


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=3000)
