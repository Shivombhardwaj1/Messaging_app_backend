from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit, join_room
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from pymongo import MongoClient
import datetime

# ---------------------------
# App & Config
# ---------------------------
app = Flask(__name__)
CORS(app)
bcrypt = Bcrypt(app)
app.config["JWT_SECRET_KEY"] = "secret123"
jwt = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# ---------------------------
# MongoDB Connection
# ---------------------------
client = MongoClient("mongodb+srv://test:test123@cluster0.vklgwvt.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
db = client["chat_app"]        # database
users_col = db["users"]        # collection for users
messages_col = db["messages"]  # collection for chat messages

# ---------------------------
# Auth APIs
# ---------------------------
@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data["username"]
    password = bcrypt.generate_password_hash(data["password"]).decode("utf-8")
    
    if users_col.find_one({"username": username}):
        return jsonify({"msg": "User already exists"}), 400
    
    users_col.insert_one({"username": username, "password": password})
    return jsonify({"msg": "Registered successfully"}), 201


@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data["username"]
    user = users_col.find_one({"username": username})
    
    if not user or not bcrypt.check_password_hash(user["password"], data["password"]):
        return jsonify({"msg": "Invalid credentials"}), 401
    
    token = create_access_token(identity=username, expires_delta=datetime.timedelta(hours=1))
    return jsonify({"token": token})


# ---------------------------
# WebSocket Events
# ---------------------------

@socketio.on("connect")
def handle_connect():
    print("Client connected")

@socketio.on("message")
def handle_message(data):
    """
    data = {
        "username": "shiv",
        "message": "Hello world",
        "room": "general"
    }
    """
    # Save to DB
    messages_col.insert_one({
        "username": data["username"],
        "message": data["message"],
        "room": data.get("room", "general"),
        "timestamp": datetime.datetime.utcnow()
    })
    
    # Broadcast message to all in room
    emit("message", data, broadcast=True)

@socketio.on("join")
def on_join(data):
    room = data["room"]
    join_room(room)
    emit("message", {"username": "System", "message": f"{data['username']} joined {room}"}, room=room)

@socketio.on("disconnect")
def handle_disconnect():
    print("Client disconnected")

# ---------------------------
# REST API for Chat History
# ---------------------------
@app.route("/messages/<room>", methods=["GET"])
@jwt_required()
def get_messages(room):
    msgs = list(messages_col.find({"room": room}).sort("timestamp", -1).limit(20))
    # convert ObjectId & datetime to string
    for m in msgs:
        m["_id"] = str(m["_id"])
        m["timestamp"] = m["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
    return jsonify(msgs)

if __name__ == "__main__":
    if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)

