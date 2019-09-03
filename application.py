import os
import sqlite3

                                                #Try use url_for() and make templetes of it. This makes making changes easy and quick
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash # checkout this unofficial snippet
                                                                          # http://flask.pocoo.org/docs/1.0/tutorial/views/?highlight=generate_password_hash
                                                                          # and http://werkzeug.pocoo.org/docs/0.14/utils/
 
from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True      #Also app.config["SECRET_KEY"] = 'gfe87fgqe9igfigqe' makes a secret key to be used
                                                #Goto http://flask.pocoo.org/docs/1.0/config/ to know about builtin config values
                                                
# Ensure responses aren't cached so fresh data from the server are used instead of caches
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use (temporary) filesystem (instead of signed cookies) and hence won't use a SECRET_KEY  
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

# Configure CS50 Library to use SQLite database
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

    def __repr__(self):
        return ("User('{self.username}')")

@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    return apology("TODO")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    return apology("TODO")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    return apology("TODO")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    # Forget any user_id
    session.clear()
    current_user = request.form.get("username") 
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):        #to retrieve post data:request.form.get("name"), to retrieve a get data: request.args.get(), 
                                                    #or in general: request.valuse.get()
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = User.query.filter_by(username='current_user').first().username   #html template <input username="username"..> is used to retrieve the username
        

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows.password, request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = user.id        # as db.execute returns an array 
                                            # also user_id is stored in session.
                                            # See https://www.tutorialspoint.com/flask/flask_sessions.htm

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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    return apology("TODO")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    #clear session to use new data for new user 
    session.clear()
    given_username = request.form.get("username")
    # when form is submitted

    if request.method == "POST":

        # username and passswords field aren't blank

        if not given_username:
            return apology("must have username", 403)

        elif not request.form.get("password"):
            return apology("must have a password", 403)

        elif not request.form.get("confirm_password"):
            return apology("confirm password", 403)

        # validating password

        elif request.form.get("password") != request.form.get("confirm_password"):     
            return apology("passwords don't match!", 403)

        # unique username

        elif User.query.filter_by(username=given_username) == None:                      
            return apology("Username already exists.", 403)


        # adding user to database (no use of inverted commas "" or '')
        user = User(username=given_username, password=generate_password_hash(request.form.get('password')))
        db.session.add(user)
        db.session.commit()

        # add unique id in session

        session["user_id"] = user.id
        return("/")

    # if reached via GET 
    
    else:
        return render_template("register.html")

 
@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    return apology("TODO")


def errorhandler(e):
    """Handle error"""
    return apology(e.name, e.code)


# listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)


# use wt_forms flask, youtube: Corey Schaffer


if __name__ == "__main__":
    app.run(debug=True)
