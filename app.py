from urllib.parse import uses_relative

from PIL import Image, ImageOps
from flask import Flask, render_template, send_from_directory, redirect, request, make_response, url_for, jsonify, abort
from pymongo import MongoClient
from flask_socketio import SocketIO, emit, join_room, leave_room
import hashlib
import os
import uuid
import json
import time
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from flask_cors import CORS
import threading

app = Flask(__name__, template_folder="templates", static_folder="static")

CORS(app, supports_credentials=True)
# Initialize SocketIO and set the CORS option

socketio = SocketIO(app, cors_allowed_origins="*")
UPLOAD_FOLDER = 'images'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# -- Start rate limit code
# Configure Flask-Limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    # Default behavior: Limit to 50 requests in 10 seconds and block for 30 seconds
    default_limits=["50 per 10 seconds"],
    storage_uri="memory://",  # we could hook mongo into this
)

# so instead we doing it hot
blocked_ips = {}


def is_blocked(ip):
    current_time = time.time()
    if ip in blocked_ips and blocked_ips[ip] > current_time:
        return True
    elif ip in blocked_ips and blocked_ips[ip] <= current_time:
        # Unblock
        del blocked_ips[ip]
    return False


def block_ip(ip):
    block_duration = 30  # seconds
    blocked_ips[ip] = time.time() + block_duration


# -- end rate limit starter


docker_db = os.environ.get('DOCKER_DB', "false")

if docker_db == "true":
    print("using docker compose db")
    MC = MongoClient("mongo")
else:
    print("using local db")
    MC = MongoClient("localhost")

database = MC["La_fromage"]
user_data = database["users"]
posts_data = database["posts"]
moz_data = database["Mozzarella"]
ched_data = database["Cheddar"]
brie_data = database["Brie"]


def changecolorgen(user):
    changedcolor = None
    if user is not None and user.get("profilecolor") is not None:
        hexval = {"red": "#FF7276", "pink": "#fff0f0", "orange": "#ffd6a5", "yellow": "#fbf8cc", "green": "#b9fbc0",
                  "blue": "#bcf4de", "purple": "#b8b8ff"}
        colorlist = user["profilecolor"]
        colorstring = ""
        for colors in colorlist:
            colors = hexval[colors]
            colorstring += ", " + colors
        changedcolor = "background: linear-gradient(0deg" + colorstring + " 100%)!important;"
    return changedcolor


def check_user(authtoken):
    hashed_auth = hashlib.sha256(authtoken.encode()).hexdigest()
    found_user = user_data.find_one({"authtoken": hashed_auth})
    if found_user is None:
        return
    else:
        return found_user


def check_custom_dict_and_matches(custom_dict, matches):
    for mat in matches:
        if custom_dict["username"] == mat["username"]:
            return False
    return True


def recommendation_gen_algo(cheese_list, liked_user_list):
    matches = []
    for one_cheese in cheese_list:
        if one_cheese == "Mozzarella":
            mat = moz_data.find({})
            for person in mat:
                custom_dict = person
                bo = check_custom_dict_and_matches(custom_dict, matches)
                if bo and custom_dict["username"] not in liked_user_list:
                    matches.append(custom_dict)
        elif one_cheese == "Brie":
            mat = brie_data.find({})
            for person in mat:
                custom_dict = person
                bo = check_custom_dict_and_matches(custom_dict, matches)
                if bo and custom_dict["username"] not in liked_user_list:
                    matches.append(custom_dict)
        else:
            mat = ched_data.find({})
            for person in mat:
                custom_dict = person
                bo = check_custom_dict_and_matches(custom_dict, matches)
                if bo and custom_dict["username"] not in liked_user_list:
                    matches.append(custom_dict)
    second_list = user_data.find({})
    for all_people in second_list:
        custom_dict = all_people
        bo = check_custom_dict_and_matches(custom_dict, matches)
        if bo and custom_dict["username"] not in liked_user_list:
            matches.append(custom_dict)
    return matches


# Rate limit
@app.before_request
def check_blocking():
    ip = get_remote_address()
    if is_blocked(ip):
        abort(429)

    # Check Flask-Limiter
    # I have officially lost myself in how im blocking the ip
    # HOW DID I MISS THAT LINE IT WORKS NOW
    try:
        limiter.check()
    except Exception:
        block_ip(ip)
        abort(429)


@app.errorhandler(429)
def ratelimit_exceeded(e):
    ip = get_remote_address()
    block_ip(ip)
    return jsonify(error="Rate limit exceeded. Leave my app alone. You are blocked for 30 seconds."), 429


# Update active users dynamically
def update_user_list():
    users = [entry["username"] for entry in active_users if "username" in entry]
    socketio.emit('update_user_list', users)


@app.after_request
def add_nosniff(response):
    # if "X-Content-Type-Options" in response.headers:
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


active_users = []


@socketio.on('connect')
def handle_connect():
    authtoken = request.cookies.get('authtoken', "")
    user = check_user(authtoken)
    if not user or user is None:
        emit('error', {'message': 'Unauthorized'})
        return False
    else:
        username = user.get("username", "Guest")
        flag = True
        for users in active_users:
            if users["username"] == username:
                flag = False
        if flag:
            active_users.append({"username": username, "timeOn": time.time(), "profilepic": user.get("profilepic")})
        emit("user", active_users, broadcast=True)
        update_user_list()
        emit("updateTimer", {"username": username, "timeOn": 0, "profilepic": user.get("profilepic")})


@socketio.on('disconnect')
def handle_disconnect():
    authtoken = request.cookies.get('authtoken')
    user = check_user(authtoken) if authtoken else None
    if user and user is not None:
        username = user.get("username")
        for activeuser in active_users:
            if activeuser["username"] == username:
                active_users.remove(activeuser)
                emit("user_disconnected", active_users, broadcast=True)
                update_user_list()


@socketio.on('chat_message')
def handle_chat_message(data):
    authtoken = request.cookies.get('authtoken')
    user = check_user(authtoken)
    username = user.get("username", "Guest")
    message = data.get("message", "")
    if message:
        emit('chat_message', {"username": username, "message": message}, broadcast=True)


@socketio.on('new_post')
def handle_new_post(data):
    authtoken = request.cookies.get('authtoken')
    user = check_user(authtoken) if authtoken else "Guest"
    username = user.get("username", "Guest")
    post_content = data.get("content", "")
    if post_content:
        post_id = str(uuid.uuid4())
        posts_data.insert_one({"post_id": post_id, "content": post_content, "author": username})
        emit('new_post', {"post_id": post_id, "author": username, "content": post_content}, broadcast=True)


@socketio.on('join')
def handle_join(data):
    room = data.get('room', 'default')
    authtoken = request.cookies.get('authtoken')
    user = check_user(authtoken)
    username = user.get("username", "Guest")
    join_room(room)
    emit('status', {'message': f'{username} joined {room}'}, room=room)


@socketio.on('leave')
def handle_leave(data):
    room = data.get('room', 'default')
    authtoken = request.cookies.get('authtoken')
    user = check_user(authtoken)
    username = user.get("username", "Guest")
    leave_room(room)
    emit('status', {'message': f'{username} left {room}'}, room=room)


@app.route('/posts', methods=['GET'])
def get_posts():
    posts = list(posts_data.find({}, {"_id": 0}))
    return jsonify(posts)


def find_user_file_with_username(username):
    found_user = user_data.find_one({"username": username})
    if found_user is None:
        return
    else:
        return found_user


@app.route("/")
def serve_first():
    colorChange = changecolorgen
    cheesebannerlink = url_for('static', filename='cheesebanner.jpg')
    if "authtoken" in request.cookies:
        authtoken = request.cookies.get("authtoken")
        user = check_user(authtoken)
        if user is None:
            matches = user_data.find({})
            liked_users = []
            response = make_response(render_template("index.html", dates=liked_users, soon_to_be_dates=matches,
                                                     cheesebannerlink=cheesebannerlink, colorchangegen=colorChange))
            response.headers["Content-Type"] = "text/html"

            return response
        else:

            cheese_list = user["cheese"]
            matches = recommendation_gen_algo(cheese_list, user["liked_user"])
            liked_users = []
            for every_like in user["liked_user"]:
                user_file = find_user_file_with_username(every_like)
                if user_file is not None:
                    liked_users.append(user_file)

            response = make_response(
                render_template("index.html", dates=liked_users, soon_to_be_dates=matches, user=user["username"],
                                cheesebannerlink=cheesebannerlink, colorchangegen=colorChange))
            response.headers["Content-Type"] = "text/html"

            return response

    matches = user_data.find({})
    liked_users = []

    response = make_response(render_template("index.html", dates=liked_users, soon_to_be_dates=matches, user=None,
                                             cheesebannerlink=cheesebannerlink, colorchangegen=colorChange))
    response.headers["Content-Type"] = "text/html"
    return response


@app.route("/register")
def serve_signup():
    response = make_response(render_template("register.html"))
    response.headers["Content-Type"] = "text/html"
    return response


@app.route("/dms")
def serve_dms():
    response = make_response(render_template("dms.html"))
    response.headers["Content-Type"] = "text/html"
    return response


DMdata = {}


def addDMmessage(user1, user2, message):
    # Create a consistent key for the conversation
    conversation_key = f"{user1}_{user2}" if f"{user1}_{user2}" in DMdata else f"{user2}_{user1}"

    # Initialize the conversation if it doesn't exist
    if conversation_key not in DMdata:
        DMdata[conversation_key] = []

    # Append the message to the conversation
    DMdata[conversation_key].append({
        "sender": user1,
        "message": message
    })


def getDMstruct(user1, user2):
    # Create a consistent key for the conversation
    conversation_key = f"{user1}_{user2}" if f"{user1}_{user2}" in DMdata else f"{user2}_{user1}"

    # Return the conversation if it exists
    return DMdata.get(conversation_key, [])


@socketio.on('send_dm_message')
def handle_dm_message(data):
    authtoken = request.cookies.get('authtoken')
    user = check_user(authtoken)
    if not user:
        return {"status": "error", "message": "Unauthorized"}

    sender = user.get("username", "Guest")
    recipient = data.get('recipient', "")
    message = data.get('message', "")

    if not recipient or not message:
        return {"status": "error", "message": "Recipient or message missing"}

    # Add the message to the DM structure
    addDMmessage(sender, recipient, message)

    # Notify the recipient if connected
    emit("dm_message", {"username": sender, "message": message, "recipient": recipient}, broadcast=True)

    return {"status": "success"}


@socketio.on("get_dm_message_history")
def handle_get_dm_message_history(data):
    authtoken = request.cookies.get('authtoken')
    user = check_user(authtoken)
    username = user.get("username", "Guest")
    recipient = data.get('recipient', "")

    if username == "Guest" or not recipient:
        emit('error', {'message': 'Invalid request'})
        return

    # Retrieve the conversation history
    history = getDMstruct(username, recipient)
    emit("return_dm_history", {"history": history})


@socketio.on("get_user_list")
def handle_get_user_list(data=None):
    authtoken = request.cookies.get("authtoken")
    user = check_user(authtoken)
    if user == "None" or user is None:
        emit("error", {"message": "Unauthorized"})
        return

    # Emit the current active user list
    emit("user_list", {"users": list(active_users)})


@app.route("/get_dm_users", methods=["GET"])
def get_dm_users():
    fin_data = posts_data.find({})
    users = []
    for entry in fin_data:
        if "username" in entry:
            users.append(entry["username"])
    return jsonify({"users": users})


@app.route("/get_current_user", methods=["GET"])
def get_current_user():
    authtoken = request.cookies.get("authtoken")
    user = check_user(authtoken)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"username": user["username"]}), 200


@app.route("/login")
def serve_login():
    response = make_response(render_template("login.html"))
    response.headers["Content-Type"] = "text/html"
    return response


@app.route("/logout")
def logout():
    authtoken = request.cookies.get("authtoken")
    user = check_user(authtoken)
    if user != None:
        user_data.update_one({"username": user["username"]}, {"$set": {"authtoken": ""}})
    response = make_response(redirect("/"))
    response.set_cookie("authtoken", authtoken, httponly=True, max_age=-3600)
    return response


@app.route("/createAccount", methods=["POST"])
def create_user():
    username = request.form.get("username")
    password = request.form.get("password")
    moz = request.form.get("Mozzarella")
    ched = request.form.get("Cheddar")
    brie = request.form.get("Brie")
    age = request.form.get("age")
    catch_p = request.form.get("catchphrase")
    confirmed_password = request.form.get("confirmed_password")
    salt = "4!INkfr@fx#d"
    found_user = user_data.find_one({"username": username})
    if username == "None":
        response = make_response(render_template("register.html", username_exists=True))
        return response
    if found_user is None:
        if password == confirmed_password:
            cheese = []
            if moz == "Mozzarella":
                cheese.append("Mozzarella")
                moz_data.insert_one(
                    {"username": username, "age": age, "catchphrase": catch_p, "profilepic": "/static/default.jpg"})
            if ched == "Cheddar":
                cheese.append("Cheddar")
                ched_data.insert_one(
                    {"username": username, "age": age, "catchphrase": catch_p, "profilepic": "/static/default.jpg"})
            if brie == "Brie":
                cheese.append("Brie")
                brie_data.insert_one(
                    {"username": username, "age": age, "catchphrase": catch_p, "profilepic": "/static/default.jpg"})
            fin_pass = password + salt
            fin_pass = hashlib.sha256(fin_pass.encode()).hexdigest()
            user_data.insert_one(
                {"username": username, "password": fin_pass, "cheese": cheese, "authtoken": "", "liked_user": [],
                 "match": [], "age": age, "catchphrase": catch_p, "profilepic": "/static/default.jpg"})

            response = redirect("/login", code=302)
            return response
        else:
            response = make_response(render_template("register.html", password_mismatch=True))
            return response
    else:
        response = make_response(render_template("register.html", username_exists=True))
        return response


@app.route("/loginAccount", methods=["POST"])
def login_user():
    username = request.form.get("username")
    password = request.form.get("password")
    salt = "4!INkfr@fx#d"
    found_user = user_data.find_one({"username": username})
    if found_user is None:
        response = make_response(render_template("login.html", username_not_exist=True))
        return response
    else:
        fin_pass = password + salt
        fin_pass = hashlib.sha256(fin_pass.encode()).hexdigest()
        if found_user["password"] == fin_pass:
            auth_t = str(uuid.uuid4())
            hashed_auth_t = hashlib.sha256(auth_t.encode()).hexdigest()
            user_data.update_one({"username": username}, {"$set": {"authtoken": hashed_auth_t}})
            response = make_response(redirect("/"))
            response.set_cookie("authtoken", auth_t, httponly=True, max_age=3600)
            return response
        else:
            response = make_response(render_template("login.html", username_not_exist=True))
            return response


@app.route("/static/indexstyle.css")
def serve_css():
    response = send_from_directory("static", "indexstyle.css")
    response.headers["Content-Type"] = "text/css"
    return response


@app.route("/static/changecolor.js")
def serve_profile_js():
    response = send_from_directory("static", "changecolor.js")
    response.headers["Content-Type"] = "text/javascript"
    return response


@app.route("/profile/<username>")
def serve_profile(username):
    viewer = "None"
    if "authtoken" in request.cookies:
        authtoken = request.cookies.get("authtoken")
        viewer = check_user(authtoken)
        viewer = viewer["username"]
    user = user_data.find_one({"username": username})
    pfp = ""
    if user.get("profilepic") is not None:
        pfp = user["profilepic"]
    changecolor = None
    if user.get("profilecolor") is not None:
        changecolor = changecolorgen(user)
    response = make_response(
        render_template("profile.html", user=user["username"], catchphrase=user["catchphrase"], age=user["age"],
                        profilepic=pfp, viewer=viewer, changedcolor=changecolor))
    return response


@app.route('/images/<name>')
def download_file(name):
    return send_from_directory(app.config["UPLOAD_FOLDER"], name)


def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/profile/<username>/upload", methods=["POST"])
def save_profilepic(username):
    authtoken = request.cookies.get("authtoken")
    viewer = check_user(authtoken)
    if viewer["username"] == username:
        if 'pfp' not in request.files:
            print('No file part')
            return redirect(request.url.replace("/upload", ""))
        file = request.files['pfp']
        if file.filename == '':
            print('No selected file')
            return redirect(request.url.replace("/upload", ""))

        if file and allowed_file(file.filename):
            print('uploaded successfully')
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            with Image.open("images/" + filename) as im:
                ImageOps.fit(im, (1000, 1000)).save("images/" + filename)
            user_data.update_one({"username": username},
                                 {"$set": {"profilepic": url_for('download_file', name=filename)}})
            cheese_list = viewer["cheese"]
            for cheese in cheese_list:
                if cheese == "Mozzarella":
                    moz_data.update_one({"username": username},
                                        {"$set": {"profilepic": url_for('download_file', name=filename)}})
                elif cheese == "Cheddar":
                    ched_data.update_one({"username": username},
                                         {"$set": {"profilepic": url_for('download_file', name=filename)}})
                elif cheese == "Brie":
                    brie_data.update_one({"username": username},
                                         {"$set": {"profilepic": url_for('download_file', name=filename)}})

    return redirect(request.url.replace("/upload", ""))


@app.route("/profile/<username>/changecolor", methods=["POST"])
def changecolor(username):
    print(request.get_json())

    colors = request.json
    print(request)

    authtoken = request.cookies.get("authtoken")
    user = check_user(authtoken)
    if user is not None and user["username"] == username:
        user_data.update_one({"username": user["username"]}, {"$set": {"profilecolor": colors}})
    return redirect(request.url.replace("/changecolor", ""))


@app.route("/static/homepage.css")
def serve_css2():
    response = send_from_directory("static", "homepage.css")
    response.headers["Content-Type"] = "text/css"
    return response, 200


@app.route("/static/functions.js")
def serve_js():
    response = send_from_directory("static", "loginandcreate.js")
    response.headers["Content-Type"] = "text/javascript"
    return response, 200


@app.route("/static/profilecss.css")
def serve_profilecss():
    response = send_from_directory("static", "profilecss.css")
    response.headers["Content-Type"] = "text/css"
    return response, 200


@app.route("/static/logo.png")
def serve_logo():
    response = send_from_directory("static", "logo.png")
    response.headers["Content-Type"] = "image/png"
    return response, 200


@app.route("/like_user", methods=["POST"])
def add_user_to_like():
    req_json = request.get_json()
    if request.cookies.get("authtoken") is not None:
        user1 = check_user(request.cookies.get("authtoken"))
        user2 = req_json["user_that_got_liked"]
        if user1 == "None" or user2 == "None":
            return redirect("/", code=302)
        found_user = user_data.find_one({"username": user1.get("username")})
        liked_user = found_user["liked_user"]
        if user2 in liked_user:
            user_data.update_one({"username": user1.get("username")}, {"$pull": {"liked_user": user2}})
            return redirect("/", code=302)
        else:
            user_data.update_one({"username": user1.get("username")}, {"$push": {"liked_user": user2}})

            found_user2 = user_data.find_one({"username": user2})
            liked_user2 = found_user2["liked_user"]

            if user1.get("username") in liked_user2:
                #response = make_response(render_template("index.html",user2=user2,dates=matches,user=user1))
                return jsonify(user2), 200
        return redirect("/", code=302)

def backgroundTimer():
    # Emit active user list times from the server
    time.sleep(5)
    while True:
        compiledData = []
        for i in active_users:
            compiledData.append({
                "username": i["username"],
                "timeOn": time.time() - i["timeOn"],
            })
        socketio.emit("updateTimer", compiledData, namespace="/", to=None)
        time.sleep(1)

if __name__ == "__main__":
    # Changed block to run under socket
    # app.run(debug=True, host="0.0.0.0", port=8080)
    socketio.start_background_task(backgroundTimer)
    socketio.run(app, host="0.0.0.0", port=8080, debug=True, allow_unsafe_werkzeug=True)