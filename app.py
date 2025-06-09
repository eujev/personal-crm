from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from flask_session import Session
from helpers import apology, login_required

app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///test.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # Ensure username was submitted
        username = request.form.get("username")
        if not username:
            return apology("must provide username", 400)

        # Ensure username does not already exist
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )
        if len(rows) == 1:
            return apology("username already exists", 400)

        # Ensure password was submitted
        password = request.form.get("password")
        if not password:
            return apology("must provide password", 400)

        # Ensure password was submitted twice
        confirmation = request.form.get("confirmation")
        if not confirmation:
            return apology("must confirm the password", 400)

        # Ensure password and confirmation are identical
        if confirmation != password:
            return apology("password needs to match", 400)

        # Insert user into database
        db.execute(
            "INSERT INTO users (username, hash) VALUES(?, ?)",
            username,
            generate_password_hash(password),
        )
        id = db.execute("SELECT id FROM users WHERE username = ?", username)

        # Remember which user has logged in
        session["user_id"] = id[0]["id"]
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/add_contact", methods=["GET", "POST"])
@login_required
def add_cash():
    if request.method == "POST":
        firstname = request.form.get("firstname")
        if not firstname:
            return redirect("/")
        birthday = request.form.get("birthday")
        lastname = request.form.get("lastname")
        address = request.form.get("address")
        email = request.form.get("email")
        db.execute(
            "INSERT INTO people (firstname, lastname, birthday, address, mail, user_id) VALUES(?, ?, ?, ?, ?, ?)",
            firstname,
            lastname,
            birthday,
            address,
            email,
            session["user_id"],
        )
        flash("Added contact!")
        return redirect("/")
    else:
        return render_template("add_contact.html")


@app.route("/contacts")
@login_required
def contacts():
    """Show all contacts"""
    user_contacts = db.execute(
        "SELECT firstname, lastname, birthday FROM people WHERE user_id = ? ORDER BY firstname ASC, lastname ASC",
        session["user_id"],
    )
    return render_template("contacts.html", user_contacts=user_contacts)


@app.route("/contact/<person_id>")
@login_required
def contact(person_id):
    """Show all contacts"""
    try:
        user_contact = db.execute(
            "SELECT firstname, lastname, birthday, address, mail FROM people WHERE user_id = ? AND id = ?",
            session["user_id"],
            person_id,
        )
    except ValueError:
        return apology("Contact does not exist")
    return render_template("contact.html", contact=user_contact)


@app.route("/profile")
@login_required
def profile():
    user_row = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
    return render_template("profile.html", username=user_row[0]["username"])


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        # Ensure old password was submitted
        old_password = request.form.get("old_password")
        if not old_password:
            return apology("must provide old password", 400)

        # Ensure new password was submitted
        new_password = request.form.get("new_password")
        if not new_password:
            return apology("must provide new password", 400)

        # Ensure password was submitted twice
        confirmation = request.form.get("confirmation")
        if not confirmation:
            return apology("must confirm the new password", 400)

        # Query database for username
        user_row = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        # Ensure username exists and password is correct
        if not check_password_hash(user_row[0]["hash"], old_password):
            return apology("invalid password", 403)

        # Ensure password and confirmation are identical
        if confirmation != new_password:
            return apology("new password needs to match", 400)
        else:
            db.execute("UPDATE users SET hash = ? WHERE id = ?",
                       generate_password_hash(new_password), session["user_id"])
            flash("Password changed!")

        return redirect("/")
    else:
        return render_template("change_password.html")
