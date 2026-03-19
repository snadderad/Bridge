from flask import Flask, request, jsonify

app = Flask(__name__)

users = [
    {"username": "admin", "password": "1234"} #Admin user
]

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True)

    username = data.get("username")
    password = data.get("password")

    print(request.data)

    print(f"Received login attempt for username: {username}"
          f" with password: {password}")

    for user in users:
        if user["username"] == username and user["password"] == password:
            return jsonify({"status": "success"})

    return jsonify({"status": "fail"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000)
