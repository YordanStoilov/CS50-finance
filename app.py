import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    user_id = session["user_id"]
    username = db.execute("SELECT username FROM users WHERE id = ?", user_id)[0]["username"]
    stocks_data = db.execute(
        "SELECT cash, stock_name, quantity FROM users JOIN portfolio ON portfolio.user_id = users.id WHERE users.id=?", user_id)
    stock_balance = 0

# Put all values in dictionary
    for item in stocks_data:
        stock_price = lookup(item["stock_name"])
        item["stock_price"] = float(stock_price["price"])
        item["total_value"] = item["stock_price"] * int(item["quantity"])
        stock_balance += item["total_value"]

        item["stock_price"] = usd(item["stock_price"])
        item["total_value"] = usd(item["total_value"])

# Find cash balance and total of portfolio
    cash_balance = db.execute("SELECT cash FROM users WHERE id=?", session["user_id"])[0]["cash"]
    portfolio_total = cash_balance + stock_balance

    # Render and plug values into HTML
    return render_template("index.html",
                           username=username, stocks_data=stocks_data,
                           cash_balance=usd(cash_balance), portfolio_total=usd(portfolio_total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":

        # Get user input
        user_id = session["user_id"]
        stock = request.form.get("symbol").upper()

        try:
            qty = int(request.form.get("shares"))

        except ValueError:
            return apology("Shares must be a Positive Whole Number")

        if not stock or not qty or int(qty) <= 0:
            return apology("Please fill in the fields")

        qty = int(qty)

        # Find stock price
        try:
            stock_price = float(lookup(stock)["price"])

        except (TypeError):
            return apology("Stock does not exist")

        # Find client funds
        client_funds = float(db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"])

        # Do the math
        client_remaining_funds = client_funds - (qty * stock_price)
        if client_remaining_funds < 0:
            return apology("Insufficient funds")

        # Check if client already owns stock
        response = db.execute(
            "SELECT * FROM portfolio WHERE stock_name = ? AND user_id = ?", stock, user_id)

        # Add transaction to transactions table
        db.execute("INSERT INTO transactions (stock_name, quantity, user_id, price, type, datetime) VALUES (?, ?, ?, ?, ?, ?)",
                   stock, qty, user_id, stock_price, "BUY", datetime.now())

        if not response:
            # If it doesn't exist in portfolio table, create it
            db.execute("INSERT INTO portfolio (stock_name, quantity, user_id) VALUES (?, ?, ?)",
                       stock, qty, user_id)

        else:
            # If it exists, increment it
            db.execute(
                "UPDATE portfolio SET quantity = quantity + ? WHERE user_id = ? AND stock_name = ?", qty, user_id, stock)

        # Withdraw money from user cash
        db.execute("UPDATE users SET cash = ? WHERE id = ?", client_remaining_funds, user_id)
        return redirect("/")

    return render_template("buy.html")


@app.route("/history", methods=["GET", "POST"])
@login_required
def history():
    user_id = session["user_id"]
    username = db.execute("SELECT username FROM users WHERE id=?", user_id)[0]["username"]

    head_values = ["Date", "Action", "Stock name", "Quantity", "Price", "Trend"]
    results = db.execute(
        "SELECT datetime, type, stock_name, quantity, price FROM transactions WHERE user_id = ?", user_id)

    # Checking stock trends - is it going up or down
    for result in results:
        current_symbol = result["stock_name"]
        stock_price = float(lookup(current_symbol)["price"])

        # If stock is now more expensive:
        if stock_price > result["price"]:

            # Chart increasing emoji
            result["trend"] = "&#128200;"

        else:

            # Chart decreasing emoji
            result["trend"] = "&#128201;"

        result["price"] = usd(result["price"])

    return render_template("history.html", results=results, username=username, head_values=head_values)


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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    # Get user input
    if request.method == "POST":
        symbol = request.form.get("symbol")

        if not symbol:
            return apology("Please fill in the form", 400)

        # Find stock
        result = lookup(symbol)
        if not result:
            return apology("Symbol not found!", 400)

        print(12 * "*")
        print([result])

        return render_template("quoted.html", stocks=[result])

    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":

        # Get user input
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username or not password or not confirmation:
            return apology("Please fill in the form", 400)

        if password != confirmation:
            return apology("Passwords do not match", 400)

        # Hash password
        hashed_password = generate_password_hash(password, method='pbkdf2', salt_length=16)

        # Try to find user in DB
        user = db.execute("SELECT * FROM users WHERE username=? AND hash=?",
                          username, hashed_password)

        try:
            db.execute("INSERT INTO users (username, hash, cash) VALUES (?, ?, ?)",
                       username, hashed_password, 10_000)
            return render_template("login.html")

        except (ValueError):
            return apology("This username and/or password is already taken")

    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    # Currently it increases stock number when you sell ?!
    if request.method == "POST":
        user_id = session["user_id"]
        symbol = request.form.get("symbol").upper()
        quantity_request = int(request.form.get("shares"))

        # Check if there are values
        if not symbol or not quantity_request:
            return apology("Please fill in the fields", 403)

        # Query DB to see if user has bought that stock
        quantity_available = db.execute(
            "SELECT quantity FROM portfolio WHERE stock_name = ? AND user_id = ?", symbol, user_id)
        print(15 * "*")
        print(quantity_available)
        quantity_available = int(quantity_available[0]["quantity"])

        if not quantity_available or quantity_request > quantity_available:
            return apology("You do not have enough of that stock to sell")

        # Find stock current price
        current_stock_price = float(lookup(symbol)["price"])

        # Add transaction to table
        db.execute("INSERT INTO transactions (stock_name, quantity, user_id, price, type, datetime) VALUES (?, ?, ?, ?, ?, ?)",
                   symbol, quantity_request, user_id, current_stock_price, "SELL", datetime.now())

        # Remove stock from user's wallet

        # If user is selling all of his stock:
        if quantity_available == quantity_request:
            db.execute("DELETE FROM portfolio WHERE user_id = ? AND stock_name = ?", user_id, symbol)

        else:
            db.execute("UPDATE portfolio SET quantity = ? WHERE user_id = ? AND stock_name = ?",
                       quantity_available - quantity_request, user_id, symbol)

        # Add the money to the user's cash
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?",
                   (current_stock_price * quantity_request), user_id)

        return redirect("/")

    options = db.execute("SELECT stock_name FROM portfolio WHERE user_id = ?", session["user_id"])

    return render_template("sell.html", options=options)
