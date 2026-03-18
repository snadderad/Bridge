from flask import Flask, request, jsonify

app = Flask(__name__)

# fake database
users = [
    {"username": "admin", "password": "1234"} #Admin user
]

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    username = data.get("username")
    password = data.get("password")

    for user in users:
        if user["username"] == username and user["password"] == password:
            return jsonify({"status": "success"})

    return jsonify({"status": "fail"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000)