from flask import Flask, render_template, request, redirect, url_for, flash
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)

app = Flask(__name__)
app.secret_key = "supersecretkey"
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login_get"

# In-memory user store
users = {}

# User model
class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)

# ---------------- ROUTES ----------------

@app.route("/")
def home():
    return render_template("base.html")

# -------- Register --------
@app.route("/register", methods=["GET"])
def register_get():
    return render_template("register.html")

@app.route("/register", methods=["POST"])
def register_post():
    username = request.form.get("username")
    password = request.form.get("password")

    if username in users:
        flash("⚠️ User already exists!")
        return redirect(url_for("register_get"))

    password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
    user = User(id=username, username=username, password_hash=password_hash)
    users[username] = user
    flash("✅ Registration successful! Please log in.")
    return redirect(url_for("login_get"))

# -------- Login --------
@app.route("/login", methods=["GET"])
def login_get():
    return render_template("login_page.html")

@app.route("/login", methods=["POST"])
def login_post():
    username = request.form.get("username")
    password = request.form.get("password")
    user = users.get(username)

    if not user or not bcrypt.check_password_hash(user.password_hash, password):
        flash("❌ Invalid username or password!")
        return redirect(url_for("login_get"))

    login_user(user)
    flash(f"✅ Welcome, {username}!")
    return redirect(url_for("protected"))

# -------- Protected --------
@app.route("/protected")
@login_required
def protected():
    return render_template("protected.html", username=current_user.username)

# -------- Logout --------
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("👋 You have been logged out.")
    return redirect(url_for("home"))

# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True)
