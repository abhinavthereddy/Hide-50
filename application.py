from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from passlib.apps import custom_app_context as pwd_context
from tempfile import mkdtemp
from werkzeug import secure_filename
from flask import Flask, jsonify, render_template, request, url_for
from flask_jsglue import JSGlue
from stegano import lsb     # https://github.com/cedricbonhomme/Stegano/blob/master/README.rst
import PIL
from PIL import Image
from distutils.core import setup

from helpers import *

MAX_KEY_SIZE = 26

# configure application
app = Flask(__name__)
JSGlue(app)

# ensure responses aren't cached
if app.config["DEBUG"]:
    @app.after_request
    def after_request(response):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Expires"] = 0
        response.headers["Pragma"] = "no-cache"
        return response
# configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"

Session(app)

# configure CS50 Library to use SQLite database
db = SQL("sqlite:///data.db")


@app.route("/")
@login_required
def index():
    return render_template("index.html")
    
@app.route("/about",  methods=["GET"])
def about():
    return render_template("about.html")
    
    
@app.route("/encrypt", methods=["GET", "POST"])
@login_required
def encrypt():
    if request.method == "GET":
        return render_template("encrypt.html")
        
    else:
        if not (request.form.get("text") or request.form.get("key1")):
            return apology("Missing Message/Key")
            
        elif request.form.get("key1").isdigit() == False:
            return apology("Enter a secret  key between 1 and 26.")
            
        elif (int(request.form.get("key1")) < 1 or int(request.form.get("key1")) > MAX_KEY_SIZE):
            return apology("Enter a secret  key between 1 and 26.")
            
        else:
            f = request.files['pic']
            f.save("./static/Input.png")
            plaintext1 = request.form.get("text")
            key1 = int(request.form.get("key1"))
            ciphertext1 = ciphertexter(plaintext1, key1)
            secret = lsb.hide(f, ciphertext1)  # or secret = lsb.hide("./Input.png", text)
            secret.save("./static/Stego.png")
            return render_template("encrypted.html")
            

@app.route("/decrypt", methods=["GET", "POST"])
@login_required
def decrypt():
    if request.method == "GET":
        return render_template("decrypt.html")
        
    else:
        if not request.form.get("key2"):
            return apology("Missing Key")
        
        elif (int(request.form.get("key2")) < 1 or int(request.form.get("key2")) > MAX_KEY_SIZE):
            return apology("Invalid Key")
            
        else:
            f = request.files['pic']
            ciphertext2 = lsb.reveal(f)
            if (ciphertext2 == None):
                return apology("Uploaded image is not a stego image")
            else:
                key2 = int(request.form.get("key2"))
                plaintext2 = plaintexter(ciphertext2, key2)
                return render_template("decrypted.html", secrets = plaintext2)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in."""

    # forget any user_id
    session.clear()

    # if user reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # ensure username was submitted
        if not request.form.get("username"):
            return apology("Missing Username")

        # ensure password was submitted
        elif not request.form.get("password"):
            return apology("Missing Password")

        # query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))

        # ensure username exists and password is correct
        if len(rows) != 1 or not pwd_context.verify(request.form.get("password"), rows[0]["hash"]):
            return apology("Invalid Username and/or Password")

        # remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # redirect user to home page
        return redirect(url_for("index"))

    # else if user reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/logout")
def logout():
    """Log user out."""

    # forget any user_id
    session.clear()

    # redirect user to login form
    return redirect(url_for("login"))
    
@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user."""
    # forget any user_id
    session.clear()
    # if user reached route via POST (as by submitting a form via POST)
    if request.method == "GET":
        return render_template("register.html")
         # if user reached route via GET (as by clicking a link or via redirect)
        
    else:
        # ensure username was submitted
        if not request.form.get("username"):
            return apology("Missing Username and/or Password")

        # ensure password was submitted
        elif not request.form.get("password"):
            return apology("Missing Username and/or Password")
        
        elif not request.form.get("repassword"):
            return apology("Re-enter Password")
            
        elif request.form.get("password") != request.form.get("repassword"):
            return apology("Passwords do not match.")
            
        elif not request.form.get("email"):
            return apology("Missing Email")
        
        elif not request.form.get("remail"):
            return apology("Please re-enter Email ID")
        
        elif (('@' not in request.form.get("email")) or ('@' not in request.form.get("email"))):
            return apology("Invalid Email")
            
        elif request.form.get("email") != request.form.get("remail"):
            return apology("Email IDs do not match")
            
        elif len(db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))) != 0:
            return apology ("Username Already exists")
            
        else:
            
            hash1 = pwd_context.hash(secret = request.form.get("password"))
            db.execute("INSERT INTO users (username, hash, email) VALUES (:username, :hash1, :email)", username=request.form.get("username"), hash1 = hash1, email = request.form.get("email"))
            # remember which user has logged in
            
            rows = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))
            session["user_id"] = rows[0]["id"]

            # redirect user to home page
            return redirect(url_for("index"))
            
@app.route("/changepassword", methods=["GET", "POST"])
@login_required
def changepassword():
    """ Allows user to change password """
    
    if request.method == "GET":
        return render_template("changepassword.html")
         # if user reached route via GET (as by clicking a link or via redirect)
        
    else:
        # ensure old password was submitted
        if not request.form.get("oldpassword"):
            return apology("must enter old password")

        # ensure password was submitted
        elif not request.form.get("newpassword"):
            return apology("Please enter old password")
        
        elif not request.form.get("newrepassword"):
            return apology("re-enter new password")
            
        rows = db.execute("SELECT * FROM users WHERE id = :id1", id1 = session["user_id"])
        
        if not pwd_context.verify(request.form.get("oldpassword"), rows[0]["hash"]):
            return apology("Incorrect Password")
            
        elif request.form.get("newpassword") != request.form.get("newrepassword"):
            return apology("new passwords do not match")
        
        elif request.form.get("newpassword") == request.form.get("oldpassword"):
            return apology("new password cannot be same as old")
            
        else:
            hashnew = pwd_context.hash(secret = request.form.get("newpassword"))
            db.execute("UPDATE users SET hash = :hashnew WHERE id = :id1", hashnew = hashnew, id1 = session["user_id"])
            session.clear()
            return render_template("passwordchanged.html")