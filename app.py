from flask import Flask, render_template, request, session, url_for, redirect, flash
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

from passlib.hash import sha256_crypt

engine = create_engine("mysql+pymysql://mysql:Praveen@076@localhost/register_and_login")
# ("mysql+pymysql://username:password@localhost/database_name")
db = scoped_session(sessionmaker(bind=engine))

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


# Register page
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        secure_password = sha256_crypt.encrypt(str(password))

        if password == confirm_password:
            db.execute("INSERT INTO users(username, password) VALUES (:username, :password)",
                       {"username": username, "password": secure_password})
            db.commit()
            flash("You have registered successfully. Try to Login now.", "success")
            return redirect(url_for('login'))
        else:
            flash("Password does not match", "danger")
            return render_template("register.html")

    return render_template("register.html")


# Login page
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        usernamedata = db.execute("SELECT username FROM users WHERE username=:username",
                                  {"username": username}).fetchone()
        passworddata = db.execute("SELECT password FROM users WHERE username=:username",
                                  {"username": username}).fetchone()

        if usernamedata is None:
            flash("No username exists", "danger")
            return render_template("login.html")
        else:
            for passwords in passworddata:
                if sha256_crypt.verify(password, passwords):
                    session["log"] = True
                    flash("You are logged in", "success")
                    return redirect(url_for('photo'))
                else:
                    flash("Incorrect username or password", "danger")
                    return render_template("login.html")

    return render_template("login.html")


# Photo page
@app.route("/photo")
def photo():
    return render_template("photo.html")


# Logout
@app.route("/logout")
def logout():
    flash("You are logged out.", "success")
    session.clear()
    # return render_template("index.html")
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.secret_key = "Praveen@076"
    app.run(debug=True)
