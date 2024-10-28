from flask import Flask, render_template, send_from_directory, redirect, request, make_response, url_for
from pymongo import MongoClient
import hashlib
import os
import uuid

app = Flask(__name__, template_folder="templates")

MC = MongoClient("mongo")
database = MC["La_fromage"]
user_data = database["users"]
moz_data = database["Mozeralla"]
ched_data = database["Cheddar"]
brie_data = database["Brie"]

def check_user(authtoken):
    hashed_auth = hashlib.sha256(authtoken.encode()).hexdigest()
    found_user = user_data.find_one({"authtoken": hashed_auth})
    if found_user is None:
        return "None"
    else:
        return found_user
    
def recommendation_gen_algo(cheese_list):
    matches = []
    for one_cheese in cheese_list:
        if one_cheese == "Mozeralla":
            mat = moz_data.find({})
            for person in mat:
                custom_dict = {"username":person["username"], "age":person["age"], "catchphrase": person["catchphrase"]}
                if custom_dict not in matches:
                    matches.append(custom_dict)
        elif one_cheese == "Brie":
            mat = brie_data.find({})
            for person in mat:
                custom_dict = {"username":person["username"], "age":person["age"], "catchphrase": person["catchphrase"]}
                if custom_dict not in matches:
                    matches.append(custom_dict)
        else:
            mat = ched_data.find({})
            for person in mat:
                custom_dict = {"username":person["username"], "age":person["age"], "catchphrase": person["catchphrase"]}
                if custom_dict not in matches:
                    matches.append(custom_dict)
    second_list = user_data.find({})
    for all_people in second_list:
        custom_dict = {"username":all_people["username"], "age":all_people["age"], "catchphrase": all_people["catchphrase"]}
        if custom_dict not in matches:
            matches.append(custom_dict)
    return matches

@app.after_request
def add_nosniff(response):
    # if "X-Content-Type-Options" in response.headers:
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

@app.route("/")
def serve_first():
    if "authtoken" in request.cookies:
        authtoken = request.cookies.get("authtoken")
        user = check_user(authtoken)
        if user == "None":
            matches = user_data.find({})
            response = make_response(render_template("index.html", dates=matches, user= "None"))
            response.headers["Content-Type"] = "text/html"
            return response
        else:
            cheese_list = user["cheese"]
            matches = recommendation_gen_algo(cheese_list)
            response = make_response(render_template("index.html", dates=matches, user=user["username"]))
            response.headers["Content-Type"] = "text/html"
            return response
            
    matches = user_data.find({})
    response = make_response(render_template("index.html",dates=matches, user= "None"))
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

@app.route("/logout")
def logout():
    authtoken = request.cookies.get("authtoken")
    user = check_user(authtoken)
    if user != "None":
        user_data.update_one({"username": user["username"]},{"$set" : {"authtoken": ""}})
    response = make_response(redirect("/"))
    response.set_cookie("authtoken", authtoken, httponly = True, max_age=-3600)
    return response

@app.route("/createAccount",methods=["POST"])
def create_user():
    username = request.form.get("username")
    password = request.form.get("password")
    moz = request.form.get("Mozeralla")
    ched = request.form.get("Cheddar")
    brie = request.form.get("Brie")
    age = request.form.get("age")
    catch_p = request.form.get("catchphrase")
    confirmed_password = request.form.get("confirmed_password")
    salt = "4!INkfr@fx#d"
    found_user = user_data.find_one({"username": username})
    if username == "None":
        response = make_response(render_template("register.html",username_exists = True))
        return response
    if found_user is None:
        if password == confirmed_password:
            cheese = []
            if moz == "yes":
                cheese.append("Mozeralla")
                moz_data.insert_one({"username":username,"age":age,"catchphrase":catch_p})
            if ched == "yes":
                cheese.append("Cheddar")
                ched_data.insert_one({"username":username,"age":age,"catchphrase":catch_p})
            if brie == "yes":
                cheese.append("Brie")
                brie_data.insert_one({"username":username,"age":age,"catchphrase":catch_p})
            fin_pass = password + salt
            fin_pass = hashlib.sha256(fin_pass.encode()).hexdigest()
            user_data.insert_one({"username": username, "password": fin_pass, "cheese": cheese,"authtoken": "","liked_user":[],"match":[],"age":age,"catchphrase":catch_p})
            
            response = redirect("/login",code=302)
            return response
        else:
            response = make_response(render_template("register.html",password_mismatch = True))
            return response
    else:
        response = make_response(render_template("register.html",username_exists = True))
        return response

@app.route("/loginAccount",methods=["POST"])
def login_user():
    username = request.form.get("username")
    password = request.form.get("password")
    salt = "4!INkfr@fx#d"
    found_user = user_data.find_one({"username": username})
    if found_user is None:
        response = make_response(render_template("login.html", username_not_exist = True))
        return response
    else:
        fin_pass = password + salt
        fin_pass = hashlib.sha256(fin_pass.encode()).hexdigest()
        if found_user["password"] == fin_pass:
            auth_t = str(uuid.uuid4())
            hashed_auth_t = hashlib.sha256(auth_t.encode()).hexdigest()
            user_data.update_one({"username": username},{"$set" : {"authtoken": hashed_auth_t}})
            response = make_response(redirect("/"))
            response.set_cookie("authtoken", auth_t, httponly = True, max_age=3600)
            return response
        else:
            response = make_response(render_template("login.html",username_not_exist = True))
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
    response = send_from_directory("/static","loginandcreate.js")
    response.headers["Content-Type"] = "text/javascript"
    return response, 200

@app.route("/static/logo.png")
def serve_logo():
    response = send_from_directory("/static","logo.png")
    response.headers["Content-Type"] = "image/png"
    return response, 200

@app.route("/like_user", methods=["POST"])
def add_user_to_like():
    req_json = request.get_json()
    user1 = req_json["user_that_likes"]
    user2 = req_json["user_that_got_liked"]
    if user1 == "None" or user2 == "None":
        return redirect("/",code=302)
    found_user = user_data.find_one({"username":user1})
    liked_user = found_user["liked_user"]
    matches = recommendation_gen_algo(found_user["cheese"])
    if user2 in liked_user:
        liked_user.remove(user2)
        user_data.update_one({"username":user1},{"$set" : {"liked_user": liked_user}})
        return redirect("/",code=302)
    else:
        liked_user.append(user2)
        user_data.update_one({"username":user1},{"$set" : {"liked_user": liked_user}})
        found_user2 = user_data.find_one({"username":user2})
        liked_user2 = found_user2["liked_user"]
        if user1 in liked_user2:
            response = make_response(render_template("index.html",user2=user2,dates=matches,user=user1))
            return response
        return redirect("/",code=302)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8080)