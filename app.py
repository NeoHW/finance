import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

from datetime import datetime

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


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
    # Get symbols and total number of shares for each symbol
    rows = db.execute(
        "SELECT symbol, SUM(shares) as totalShares FROM transactions WHERE person_id = ? GROUP BY symbol HAVING totalShares  > 0 ", session["user_id"])

    # Create an empty tuple(ordered values)
    stock = []
    total = 0
    for row in rows:
        # Info containts name, price & symbol; use row["totalshares"] to get number of shares
        info = lookup(row["symbol"])
        stock.append({
            "symbol": info["symbol"],
            "name": info["name"],
            "shares": row["totalShares"],
            "price": usd(info["price"]),
            "stock_value": usd(info["price"] * row["totalShares"])
        })
        total += info["price"] * row["totalShares"]

    # Amt of cash available
    cash = db.execute("SELECT cash FROM users WHERE id = ? ", session["user_id"])[0]['cash']

    # Total amt of money including cash and stock_value
    total += cash

    return render_template("index.html", rows=stock, cash=usd(cash), total=usd(total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        symbol = request.form.get("symbol")
        try:
            shares = int(request.form.get("shares"))  # Change it from string to int!
        except ValueError:
            return apology("shares must be a postive int", 400)

        # Ensure symbol was submitted
        if not symbol:
            return apology("missing symbol", 400)

        # Ensure shares was submitted
        if not shares:
            return apology("missing shares", 400)

        # Ensure symbol exists
        if lookup(symbol) == None:
            return apology("invalid symbol", 400)

        # Ensure shares are positive
        if shares < 0:
            return apology("input positive integer", 400)

        # Lookup current stock price
        quote = lookup(request.form.get("symbol"))
        price = quote["price"]

        # Total cash user is using
        total = shares * price

        # Check current cash of user
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        cash = cash[0]['cash']

        # Ensure user has enough cash to afford stock, if not return apology
        if cash < total:
            return apology("not enough cash", 400)
        else:
            # Run SQL statement on database to purchase stock | # FIND ANSWER : !!! Why can't NOW() be used in sqlite itself? !!!
            db.execute("INSERT INTO transactions (person_id, shares, symbol, price, transacted) VALUES(?,?,?,?,?)",
                       session["user_id"], shares, symbol, price, datetime.now())

            # Update cash to reflected purchased stock
            cash -= total
            db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, session["user_id"])

            return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    # Get all necessary information from transaction table
    rows = db.execute("SELECT * FROM transactions WHERE person_id = ? ORDER BY transacted DESC", session["user_id"])

    return render_template("history.html", rows=rows)


@app.route("/login", methods=["GET", "POST"])
def login():
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
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
    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "POST":
        symbol = request.form.get("symbol")

        info = lookup(request.form.get("symbol"))

        # Ensure quote is not blank
        if not symbol:
            return apology("missing symbol", 400)

        # Ensure quote symbol exists
        elif lookup(symbol) == None:
            return apology("invalid symbol", 400)

        quote = lookup(request.form.get("symbol"))
        return render_template("quoted.html", quote=quote)

    # User reached route via GET
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        special_characters = " !\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"

        # Ensure username was submitted
        if not username:
            return apology("missing username", 400)

        # Ensure password was submitted
        elif not password:
            return apology("missing password", 400)

        # Ensure password matches
        elif password != confirmation:
            return apology("password don't match", 400)

        # Ensure username is not already in use
        elif len(db.execute("SELECT * FROM users WHERE username = ?", username)) != 0:
            return apology("username taken", 400)

        # CREATE PASSWORD FEATURES (one special character)

        # Min 8 chars
        if len(password) < 8:
            return apology("password must contain over 8 characters", 400)

        # both numbers and digits must be available
        elif not any(q.isdigit() for q in password):
            return apology("password must contain a digit", 400)
        elif not any(q.isalpha() for q in password):
            return apology("password must contain an alphabetic letter", 400)

        # mix of uppercase & lower
        elif not any(q.isupper() for q in password):
            return apology("password must contain uppercase letter", 400)
        elif not any(q.islower() for q in password):
            return apology("password must contain lowercase letter", 400)

        # check for special characters
        elif not any(q in special_characters for q in password):
            return apology("password must contain special character", 400)

        # Generate password hash and add data in database
        pwhash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        db.execute("INSERT INTO users (username,hash) VALUES (?,?)", username, pwhash)

        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    rows = db.execute(
        "SELECT symbol, SUM(shares) as totalShares FROM transactions WHERE person_id = ? GROUP BY symbol HAVING totalShares > 0 ", session["user_id"])

    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        info = lookup(request.form.get("symbol"))
        price = info["price"]

        # Ensure symbol was submitted
        if not symbol:
            return apology("missing symbol", 400)

        # Ensure shares was submitted
        elif not shares:
            return apology("missing shares", 400)

        # Ensure symbol exists
        elif lookup(symbol) == None:
            return apology("invalid symbol", 400)

        # Ensure number of shares is not text
        elif not shares.isdigit():
            return apology("Invalid number of shares", 400)

        # Ensure user do not sell more share than they own
        for row in rows:
            if row["symbol"] == symbol:
                if int(shares) > row["totalShares"]:
                    return apology("you do not have enough shares")

        # User's Current Cash
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        cash = cash[0]['cash']
        # Update User's Cash
        new_cash = cash + int(shares) * price
        db.execute("UPDATE users SET cash = ? WHERE id = ?", new_cash, session["user_id"])

        # Update database transactions, remember to make shares negative as we're selling
        db.execute("INSERT INTO transactions (person_id, shares, symbol, price, transacted) VALUES(?,?,?,?,?)",
                   session["user_id"], (int(shares) * -1), symbol, price, datetime.now())

        return redirect("/")

    else:
        return render_template("sell.html", rows=rows)