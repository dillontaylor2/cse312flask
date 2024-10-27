from flask import Flask, render_template, send_from_directory, redirect, request, make_response
from pymongo import MongoClient
import hashlib
import os
import uuid

app = Flask(__name__, template_folder="templates")

MC = MongoClient("mongo")
database = MC["La_fromage"]
user_data = database["users"]

def check_user(authtoken):
    hashed_auth = hashlib.sha256(authtoken.encode()).hexdigest()
    found_user = user_data.find_one({"authtoken": hashed_auth})
    if found_user is None:
        return "None"
    else:
        return found_user

@app.after_request
def add_nosniff(response):
    if "X-Content-Type-Options" in response.headers:
        response.headers["X-Content-Type-Options"] = "nosniff"
    return response

@app.route("/")
def serve_first():
    if "authtoken" in request.cookies:
        authtoken = request.cookies.get("authtoken")
        user = check_user(authtoken)
        if user == "None":
            matches = user_data.find({})
            response = make_response(render_template("index.html"), dates=matches)
            response.headers["Content-Type"] = "text/html"
            return response
        else:
            matches = user_data.find({"cheese":user["cheese"]})
            second_matches = user_data.find({})
            response = make_response(render_template("index.html"), dates=matches)
            response.headers["Content-Type"] = "text/html"
            return response
            
    matches = user_data.find({})
    if matches is None:
        response = make_response(render_template("index.html"))
    else:
        response = make_response(render_template("index.html",dates=matches))
    response.headers["Content-Type"] = "text/html"
    return response

@app.route("/register")
def serve_signup():
    response = make_response(render_template("register.html"))
    response.headers["Content-Type"] = "text/html"
    return response

@app.route("/login")
def serve_login():
    response = make_response(render_template("login.html"))
    response.headers["Content-Type"] = "text/html"
    return response

@app.route("/createAccount",methods=["POST"])
def create_user():
    username = request.form.get("username")
    password = request.form.get("password")
    cheese = request.form.get("cheese")
    confirmed_password = request.form.get("confirmed_password")
    salt = "4!INkfr@fx#d"
    found_user = user_data.find_one({"username": username})
    if found_user is None:
        if password == confirmed_password:
            fin_pass = password + salt
            fin_pass = hashlib.sha256(fin_pass.encode()).hexdigest()
            user_data.insert_one({"username": username, "password": fin_pass, "cheese": cheese,"authtoken": "","liked_user":[],"match":[]})
            response = redirect("/login",code=302)
            return response
        else:
            response = make_response(render_template("register.html"),password_mismatch = True)
            return response
    else:
        response = make_response(render_template("register.html"),username_exists = True)
        return response

@app.route("/loginAccount",methods=["POST"])
def login_user():
    username = request.form.get("username")
    password = request.form.get("password")
    salt = "4!INkfr@fx#d"
    found_user = user_data.find_one({"username": username})
    if found_user is None:
        response = make_response(render_template("login.html"), username_not_exist = True)
        return response
    else:
        fin_pass = password + salt
        fin_pass = hashlib.sha256(fin_pass.encode()).hexdigest()
        if found_user["password"] == fin_pass:
            auth_t = uuid.uuid4()
            hashed_auth_t = hashlib.sha256(auth_t.encode()).hexdigest()
            user_data.update_one({"username": username},{"$set" : {"authtoken": hashed_auth_t}})
            response = make_response(redirect("/"),user = username)
            response.set_cookie("authtoken", auth_t, httponly = True, max_age=3600)
            return response
        else:
            response = make_response(render_template("login.html"),wrong_password = True)
            return response

@app.route("/static/indexstyle.css")
def serve_css():
    response = send_from_directory("/static","indexstyle.css")
    response.headers["Content-Type"] = "text/css"
    return response

@app.route("/static/homepage.css")
def serve_css2():
    response = send_from_directory("/static","homepage.css")
    response.headers["Content-Type"] = "text/css"
    return response, 200

@app.route("/static/functions.js")
def serve_js():
    response = send_from_directory("/static","functions.js")
    response.headers["Content-Type"] = "text/javascript"
    return response, 200

@app.route("/static/logo.png")
def serve_logo():
    response = send_from_directory("/static","logo.png")
    response.headers["Content-Type"] = "image/png"
    return response, 200

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8080)