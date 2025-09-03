import os
import json
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(BASE_DIR, "users.json")
POSTS_FILE = os.path.join(BASE_DIR, "posts.json")

app = Flask(__name__)

# I've hardcoded the key here for demo and simplicity, don't ever do it like that in prod :)
app.secret_key = "dev-demo-secret-key-CHANGE-ME"

def _read_json(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return default

def _write_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def load_users():
    return _read_json(USERS_FILE, [])

def save_users(users):
    _write_json(USERS_FILE, users)

def find_user(username):
    users = load_users()
    for u in users:
        if u.get("username") == username:
            return u
    return None

def require_login():
    return "user" in session

def current_user():
    return session.get("user")

def load_posts():
    return _read_json(POSTS_FILE, [])

def save_posts(posts):
    _write_json(POSTS_FILE, posts)

def find_post(pid):
    posts = load_posts()
    for p in posts:
        if p.get("id") == pid:
            return p
    return None

def _next_post_id(posts):
    return max((p.get("id", 0) for p in posts), default=0) + 1

@app.route("/", methods=["GET"])
def index():
    posts = load_posts()
    return render_template("index.html", posts=posts, user=current_user())


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html", user=current_user())

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    if not username or not password:
        flash("Username and password are required.", "danger")
        return redirect(url_for("signup"))

    if find_user(username):
        flash("Username already exists.", "warning")
        return redirect(url_for("signup"))

    users = load_users()
    users.append({
        "username": username,
        "password_hash": generate_password_hash(password)
    })
    save_users(users)
    flash("Account created. Please log in.", "success")
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", user=current_user())

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    user = find_user(username)
    if not user or not check_password_hash(user.get("password_hash", ""), password):
        flash("Invalid username or password.", "danger")
        return redirect(url_for("login"))

    session["user"] = username
    flash("Logged in successfully.", "success")
    return redirect(url_for("index"))

@app.route("/logout", methods=["POST"])
def logout():
    session.pop("user", None)
    flash("Logged out.", "info")
    return redirect(url_for("index"))

@app.route("/boom")
def boom():
    # test endpoint to cause 500 error
    raise Exception("Test 500 error")

@app.route("/posts", methods=["GET"])
def list_posts_json():
    return jsonify(load_posts())

@app.route("/posts", methods=["POST"])
def create_post():
    if not require_login():
        if request.is_json:
            return jsonify({"error": "Login required"}), 401
        flash("Please log in to create a post.", "warning")
        return redirect(url_for("login"))

    title = (request.form.get("title") or "").strip() if not request.is_json else (request.get_json(silent=True) or {}).get("title", "").strip()
    body = (request.form.get("body") or "").strip() if not request.is_json else (request.get_json(silent=True) or {}).get("body", "").strip()

    if not title or not body:
        if request.is_json:
            return jsonify({"error": "Title and body are required"}), 400
        flash("Title and body are required.", "danger")
        return redirect(url_for("index"))

    posts = load_posts()
    pid = _next_post_id(posts)
    post = {
        "id": pid,
        "author": current_user(),
        "title": title,
        "body": body,
        "comments": []
    }
    posts.append(post)
    save_posts(posts)

    if request.is_json:
        return jsonify(post), 201
    flash("Post created!", "success")
    return redirect(url_for("view_post", pid=pid))

@app.route("/post/<int:pid>", methods=["GET"])
def view_post(pid):
    post = find_post(pid)
    if not post:
        return ("Post not found", 404)
    return render_template("post.html", post=post, user=current_user())

@app.route("/post/<int:pid>/edit", methods=["POST"])
def edit_post(pid):
    post = find_post(pid)
    if not post:
        return ("Post not found", 404)
    if not require_login() or post.get("author") != current_user():
        return ("Forbidden", 403)

    title = (request.form.get("title") or "").strip()
    body = (request.form.get("body") or "").strip()
    if not title or not body:
        flash("Title and body are required.", "danger")
        return redirect(url_for("view_post", pid=pid))

    posts = load_posts()
    for p in posts:
        if p.get("id") == pid:
            p["title"] = title
            p["body"] = body
            break
    save_posts(posts)
    flash("Post updated.", "success")
    return redirect(url_for("view_post", pid=pid))

@app.route("/post/<int:pid>/comment", methods=["POST"])
def add_comment_to_post(pid):
    post = find_post(pid)
    if not post:
        return ("Post not found", 404)
    if not require_login():
        if request.is_json:
            return jsonify({"error": "Login required"}), 401
        flash("Please log in to comment.", "warning")
        return redirect(url_for("login"))

    text = (request.form.get("text") or "").strip() if not request.is_json else (request.get_json(silent=True) or {}).get("text", "").strip()
    if not text:
        if request.is_json:
            return jsonify({"error": "Missing comment text"}), 400
        flash("Comment text is required.", "danger")
        return redirect(url_for("view_post", pid=pid))

    posts = load_posts()
    for p in posts:
        if p.get("id") == pid:
            p.setdefault("comments", []).append({"author": current_user(), "text": text})
            break
    save_posts(posts)

    if request.is_json:
        return jsonify({"ok": True}), 201
    flash("Comment added.", "success")
    return redirect(url_for("view_post", pid=pid))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
