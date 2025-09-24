import os
import json
import time
import uuid
import logging
from logging.handlers import RotatingFileHandler
from functools import wraps
from flask import (
    Flask, request, jsonify, render_template, redirect,
    url_for, session, flash, g
)
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(BASE_DIR, "users.json")
POSTS_FILE = os.path.join(BASE_DIR, "posts.json")
LOG_DIR = os.path.join(BASE_DIR, "logs")

app = Flask(__name__)
# I've hardcoded the key here for demo and simplicity, don't ever do it like that in prod :)
app.secret_key = "dev-demo-secret-key-CHANGE-ME"


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, datefmt="%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key in ("request_id", "path", "method", "status", "duration_ms",
                    "ip", "user", "op", "table", "params", "rows_affected",
                    "elapsed_ms", "pid"):
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)

def _ensure_log_dir():
    os.makedirs(LOG_DIR, exist_ok=True)

def _file_handler(filename: str, level=logging.INFO) -> RotatingFileHandler:
    handler = RotatingFileHandler(
        os.path.join(LOG_DIR, filename),
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8"
    )
    handler.setLevel(level)
    handler.setFormatter(JsonFormatter())
    return handler

def configure_logging():
    _ensure_log_dir()
    app_logger = logging.getLogger("app")
    app_logger.setLevel(logging.INFO)
    app_logger.handlers.clear()
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(JsonFormatter())
    app_logger.addHandler(console)
    app_logger.addHandler(_file_handler("app.log", level=logging.INFO))
    db_logger = logging.getLogger("app.db")
    db_logger.setLevel(logging.INFO)
    db_logger.handlers.clear()
    db_console = logging.StreamHandler()
    db_console.setLevel(logging.INFO)
    db_console.setFormatter(JsonFormatter())
    db_logger.addHandler(db_console)
    db_logger.addHandler(_file_handler("db.log", level=logging.INFO))
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    app_logger.info("logging_configured", extra={"pid": os.getpid()})

configure_logging()
log = logging.getLogger("app")
dblog = logging.getLogger("app.db")


def _req_id() -> str:
    return request.headers.get("X-Request-ID") or str(uuid.uuid4())

def _user():
    return session.get("user")

def _json_load(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return default

def _json_write(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def db_op(op: str, table: str):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            start = time.time()
            try:
                result = fn(*args, **kwargs)
                rows = 0
                if isinstance(result, list):
                    rows = len(result)
                elif isinstance(result, dict):
                    rows = 1
                elapsed_ms = int((time.time() - start) * 1000)
                dblog.info(
                    f"{op} {table}",
                    extra={
                        "request_id": getattr(g, "request_id", None),
                        "op": op,
                        "table": table,
                        "params": {"args": args, "kwargs": kwargs},
                        "rows_affected": rows,
                        "elapsed_ms": elapsed_ms,
                        "user": _user()
                    }
                )
                return result
            except Exception:
                elapsed_ms = int((time.time() - start) * 1000)
                dblog.exception(
                    f"{op} {table} failed",
                    extra={
                        "request_id": getattr(g, "request_id", None),
                        "op": op,
                        "table": table,
                        "params": {"args": args, "kwargs": kwargs},
                        "elapsed_ms": elapsed_ms,
                        "user": _user()
                    }
                )
                raise
        return wrapper
    return deco


@db_op("SELECT", "users")
def load_users():
    return _json_load(USERS_FILE, [])

@db_op("WRITE", "users")
def save_users(users):
    _json_write(USERS_FILE, users)
    return {"ok": True}

@db_op("SELECT_ONE", "users")
def find_user(username):
    users = load_users()
    for u in users:
        if u.get("username") == username:
            return u
    return None

@db_op("SELECT", "posts")
def load_posts():
    return _json_load(POSTS_FILE, [])

@db_op("WRITE", "posts")
def save_posts(posts):
    _json_write(POSTS_FILE, posts)
    return {"ok": True}

@db_op("SELECT_ONE", "posts")
def find_post(pid):
    posts = load_posts()
    for p in posts:
        if p.get("id") == pid:
            return p
    return None

def _next_post_id(posts):
    return max((p.get("id", 0) for p in posts), default=0) + 1


@app.before_request
def _before():
    g.started_at = time.time()
    g.request_id = _req_id()
    log.info(
        "request_started",
        extra={
            "request_id": g.request_id,
            "method": request.method,
            "path": request.path,
            "ip": request.headers.get("X-Forwarded-For", request.remote_addr),
            "user": _user()
        }
    )

@app.after_request
def _after(resp):
    try:
        duration_ms = int((time.time() - getattr(g, "started_at", time.time())) * 1000)
        resp.headers["X-Request-ID"] = getattr(g, "request_id", "")
        log.info(
            "request_completed",
            extra={
                "request_id": getattr(g, "request_id", None),
                "method": request.method,
                "path": request.path,
                "status": resp.status_code,
                "duration_ms": duration_ms,
                "ip": request.headers.get("X-Forwarded-For", request.remote_addr),
                "user": _user()
            }
        )
    except Exception:
        log.exception("after_request_logging_failed", extra={"request_id": getattr(g, "request_id", None)})
    return resp


@app.errorhandler(400)
def _400(e):
    log.warning("bad_request", extra={"request_id": getattr(g, "request_id", None), "path": request.path})
    return ("Bad request", 400)

@app.errorhandler(403)
def _403(e):
    log.warning("forbidden", extra={"request_id": getattr(g, "request_id", None), "path": request.path, "user": _user()})
    return ("Forbidden", 403)

@app.errorhandler(404)
def _404(e):
    log.info("not_found", extra={"request_id": getattr(g, "request_id", None), "path": request.path})
    return ("Not found", 404)

@app.errorhandler(500)
def _500(e):
    log.exception("internal_error", extra={"request_id": getattr(g, "request_id", None), "path": request.path})
    return ("Internal server error", 500)


@app.route("/", methods=["GET"])
def index():
    posts = load_posts()
    return render_template("index.html", posts=posts, user=_user())

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html", user=_user())

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    if not username or not password:
        flash("Username and password are required.", "danger")
        log.warning("signup_missing_fields", extra={"request_id": g.request_id, "user": _user()})
        return redirect(url_for("signup"))

    if find_user(username):
        flash("Username already exists.", "warning")
        log.info("signup_username_taken", extra={"request_id": g.request_id, "user": _user(), "op": "signup", "params": {"username": username}})
        return redirect(url_for("signup"))

    users = load_users()
    users.append({"username": username, "password_hash": generate_password_hash(password)})
    save_users(users)
    log.info("signup_success", extra={"request_id": g.request_id, "op": "signup", "params": {"username": username}})
    flash("Account created. Please log in.", "success")
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", user=_user())

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    user = find_user(username)
    if not user or not check_password_hash(user.get("password_hash", ""), password):
        flash("Invalid username or password.", "danger")
        log.warning("login_failed", extra={"request_id": g.request_id, "op": "login", "params": {"username": username}})
        return redirect(url_for("login"))

    session["user"] = username
    log.info("login_success", extra={"request_id": g.request_id, "op": "login", "user": username})
    flash("Logged in successfully.", "success")
    return redirect(url_for("index"))

@app.route("/logout", methods=["POST"])
def logout():
    who = _user()
    session.pop("user", None)
    log.info("logout", extra={"request_id": g.request_id, "op": "logout", "user": who})
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
    if not _user():
        if request.is_json:
            return jsonify({"error": "Login required"}), 401
        flash("Please log in to create a post.", "warning")
        return redirect(url_for("login"))

    payload = request.get_json(silent=True) or {}
    title = (request.form.get("title") or "").strip() if not request.is_json else (payload.get("title") or "").strip()
    body = (request.form.get("body") or "").strip() if not request.is_json else (payload.get("body") or "").strip()

    if not title or not body:
        if request.is_json:
            return jsonify({"error": "Title and body are required"}), 400
        flash("Title and body are required.", "danger")
        return redirect(url_for("index"))

    posts = load_posts()
    pid = _next_post_id(posts)
    post = {
        "id": pid,
        "author": _user(),
        "title": title,
        "body": body,
        "comments": []
    }
    posts.append(post)
    save_posts(posts)

    log.info("post_created", extra={"request_id": g.request_id, "op": "create_post", "user": _user(), "params": {"post_id": pid, "title": title}})
    if request.is_json:
        return jsonify(post), 201
    flash("Post created!", "success")
    return redirect(url_for("view_post", pid=pid))

@app.route("/post/<int:pid>", methods=["GET"])
def view_post(pid):
    post = find_post(pid)
    if not post:
        return ("Post not found", 404)
    return render_template("post.html", post=post, user=_user())

@app.route("/post/<int:pid>/edit", methods=["POST"])
def edit_post(pid):
    post = find_post(pid)
    if not post:
        return ("Post not found", 404)
    if not _user() or post.get("author") != _user():
        log.warning("edit_forbidden", extra={"request_id": g.request_id, "op": "edit_post", "user": _user(), "params": {"post_id": pid}})
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
    log.info("post_edited", extra={"request_id": g.request_id, "op": "edit_post", "user": _user(), "params": {"post_id": pid}})
    flash("Post updated.", "success")
    return redirect(url_for("view_post", pid=pid))

@app.route("/post/<int:pid>/comment", methods=["POST"])
def add_comment_to_post(pid):
    post = find_post(pid)
    if not post:
        return ("Post not found", 404)
    if not _user():
        if request.is_json:
            return jsonify({"error": "Login required"}), 401
        flash("Please log in to comment.", "warning")
        return redirect(url_for("login"))

    payload = request.get_json(silent=True) or {}
    text = (request.form.get("text") or "").strip() if not request.is_json else (payload.get("text") or "").strip()
    if not text:
        if request.is_json:
            return jsonify({"error": "Missing comment text"}), 400
        flash("Comment text is required.", "danger")
        return redirect(url_for("view_post", pid=pid))

    posts = load_posts()
    for p in posts:
        if p.get("id") == pid:
            p.setdefault("comments", []).append({"author": _user(), "text": text})
            break
    save_posts(posts)
    log.info("comment_added", extra={"request_id": g.request_id, "op": "add_comment", "user": _user(), "params": {"post_id": pid}})
    if request.is_json:
        return jsonify({"ok": True}), 201
    flash("Comment added.", "success")
    return redirect(url_for("view_post", pid=pid))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
