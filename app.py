"""
written by zebadiah taylor for cs50. finished around 2020-12-4

Prompt, Specification: https://cs50.harvard.edu/x/2021/psets/9/finance/

See Readme.md for more information
"""

import os

from cs50 import SQL

from flask import Flask, redirect, render_template, request, session
from flask_session import Session
import sqlite3
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd


# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies, Flask's default)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")

@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Finds user's current amount of cash
    cash = db.execute("SELECT cash FROM users WHERE id = :user_id",
                user_id=session["user_id"]
                )
    cash = cash[0]["cash"]

    # finds relevant stock data
    rows = db.execute("SELECT * FROM stocks WHERE user_id = :user_id",
                user_id=session["user_id"]
                )

    # pull symbols from rows
    symbols = []
    for row in rows:
        symbols.append(row["symbol"])

    # look ups prices for symbols
    quoteds = []
    for symbol in symbols:
        quoteds.append(lookup(symbol))

    # separates stock prices into list var
    prices = []
    for quote in quoteds:
        prices.append(quote["price"])

    # inserts key:value pairs into rows: price : #
    for row in rows:
        row["price"] = prices.pop(0)

    # computes total value of shares owned per stock
    tot_share_val = 0
    for row in rows:
        tot_share_val = tot_share_val + row["shares"] * row["price"]

    return render_template("index.html", cash=cash, rows=rows, tot_share_val=tot_share_val)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    quoted = {}

    # Handles blank Stock Symbol entry.
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("Stock Symbol Required.")

        # Inserts lookup()s returned values into a dictionary.
        try:
            quoted.update(lookup(request.form.get("symbol")))

        # If bad symbol, tells user.
        except TypeError:
            return apology("No such stock exists.")

        """checks if shares input is valid"""
        sharequest = request.form.get("shares")

        if not sharequest: # checks for blanks
            return apology("gimme a number man")

        if not type(sharequest) == int:  # checks for digits and converts
            try:
                sharequest = float(sharequest)
                if sharequest % 1 != 0:
                    return apology("whole numbs only")
                else:
                    sharequest = int(sharequest)
            except (ValueError, TypeError):
                return apology("numbs only zone")
        if sharequest <= 0:    # checks for positive entry
            return apology("You can only sell 1 or more shares.")

        # Checks how much cash user has
        cash = db.execute("SELECT cash FROM users WHERE id = :user_id",
                                user_id=session["user_id"])
        cash = cash[0]["cash"]

        # Checks whether user has enough cash for purchase.
        if float(cash) < int(request.form.get("shares"))*float(quoted["price"]):
            return apology("You do not have enough money.")

        # If enough cash, updates cash in the "users" table.
        else:
            cash = float(cash) - int(request.form.get("shares"))*float(quoted["price"])
            db.execute("UPDATE users SET cash = :cash WHERE id = :user_id", cash=cash, user_id=session["user_id"])

            # Inserts transaction data into 'transactions' table.
            # note: /buy transactions are always positive values in shares
            db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES (:user_id, :symbol, :shares, :price)",
                        user_id=session["user_id"],
                        symbol=request.form.get("symbol"),
                        shares=int(request.form.get("shares")),
                        price=float(quoted["price"])
                        )

            # Checks for number of existing shares and if there's an entry. BE SURE TO INCLUDE db.execute("DELETE") IN /SELL
            shares = db.execute("SELECT shares FROM stocks WHERE user_id = :user_id AND symbol = :symbol",
                        user_id=session["user_id"],
                        symbol = request.form.get("symbol"),
                        )

            # Creates entry per stock if no current entry
            if not shares:
                db.execute("INSERT INTO stocks (user_id, symbol, shares) VALUES (:user_id, :symbol, :shares)",
                        user_id = session["user_id"],
                        symbol = request.form.get("symbol"),
                        shares = request.form.get("shares")
                        )

            else:
                # Changes dictionary format to just the value. must come after 'if not shares' above
                shares = shares[0]["shares"]
                # Adds existing shares to new shares
                shares = int(shares) + int(request.form.get("shares"))

                # Updates the stocks table.
                db.execute("UPDATE stocks SET shares = :shares WHERE user_id = :user_id AND symbol = :symbol",
                    shares=shares,
                    user_id=session["user_id"],
                    symbol=request.form.get("symbol")
                    )

        return redirect("/")

    else:
        """our helpful popular stocks feature"""
        symbols = []
        rows = db.execute("SELECT symbol FROM stocks")
        for row in rows:
            symbols.append(row["symbol"])
        return render_template("/buy.html", symbols=symbols)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    """gets transactional data relevant to user"""
    rows = db.execute("SELECT * FROM transactions WHERE user_id = :user_id",
                        user_id=session["user_id"])

    return render_template("history.html", rows=rows)


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
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

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
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "POST":
        quoted = {}

        # Inserts lookup()s returned values into a dictionary.
        try:
            quoted.update(lookup(request.form.get("symbol")))

        # Tells user that the stock symbol they typed doesn't exist.
        except TypeError:
            return apology("No such stock exists.")
            
        return render_template("/quoted.html", name=quoted["name"], price=quoted["price"], symbol=quoted["symbol"])
    
    else:
        return render_template("/quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":
        # Stores submitted username/passwords into variables.
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Checks for submitted username.
        if not username or not password or not confirmation:
            return apology("You must submit a username and a password.")

        # Taunts if passwords don't match.
        elif password != confirmation:
                return apology("LOL U CANT TYP (PASSWORDS DON'T MATCH)")

        # Queries database to see if username already exists.
        elif username:
            rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=username)
            if len(rows) == 1:
                return apology("That username is already taken. Try another.")

            else:
        # Hashes password
                hashedpw = generate_password_hash(password, method='pbkdf2:sha256')
        # All's well, info inserted into database.
                db.execute("INSERT INTO users (username, hash) VALUES (:username, :hashedpw)", username=username, hashedpw=hashedpw)
                
                return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    quoted = {}

    # Finds user's current amount of cash in user table
    cash = db.execute("SELECT cash FROM users WHERE id = :user_id",
                                user_id=session["user_id"]
                                )

    # Query returns a list of dictionaries. This gets the value we want.
    cash = cash[0]["cash"]

    # finds relevant stock data from db stocks table
    rows = db.execute("SELECT * FROM stocks WHERE user_id = :user_id",
                                user_id=session["user_id"]
                                )

    # pulls symbols from rows (for select menu)
    symbols = []
    for row in rows:
        symbols.append(row["symbol"])

    """POST: Receives sell requests"""
    if request.method == "POST":

        # Handles blank Stock Symbol entry.
        if not request.form.get("symbol"):
            return apology("Stock Symbol Required.")

        # Inserts lookup()s returned values into a dictionary.
        try:
            quoted.update(lookup(request.form.get("symbol")))
        except TypeError:
            return apology("choose a stock before you sell")

        """checks if shares are valid"""
        sharequest = request.form.get("shares")

        if not sharequest:  # checks for blanks
            return apology("gimme a number man")

        if not type(sharequest) == int:  # checks for digits and converts
            try:
                sharequest = float(sharequest)
                if sharequest % 1 != 0:
                    return apology("whole numbs only")
                else:
                    sharequest = int(sharequest)
            except (ValueError, TypeError):
                return apology("numbs only zone")
        if sharequest <= 0:    # checks for positive entry
            return apology("You can only sell 1 or more shares.")


        # Checks if user has enough shares.
        sym_found = False
        
        for row in rows:
            if request.form.get("symbol") in row.values():
                sym_found = True
                if int(request.form.get("shares")) > int(row["shares"]):
                    return apology("lol u ain't got all that")
                    break
        
        if not sym_found:
            return apology("lol did u even ever own that?")

        # If successful, adds cash to the "users" table.
        cash = float(cash) + int(request.form.get("shares"))*float(quoted["price"])
        
        db.execute("UPDATE users SET cash = :cash WHERE id = :user_id",
                                cash=cash, user_id=session["user_id"])

         # Inserts transactional data into 'transactions' table.
            # note: /sell transactions are always negatives values in shares column
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES (:user_id, :symbol, :shares, :price)",
                                user_id=session["user_id"],
                                symbol=request.form.get("symbol"),
                                shares=-1*int(request.form.get("shares")),
                                price=float(quoted["price"])
                                )

        # Calculates # of shares remaining. minimum 0.
        shares = db.execute("SELECT shares FROM stocks WHERE user_id = :user_id AND symbol = :symbol",
                                user_id=session["user_id"],
                                symbol=request.form.get("symbol")
                                )

        # Cleans that data a bit
        shares = shares[0]["shares"]
        shares = shares - int(request.form.get("shares"))

        # Just catching major errors in case above precautions don't do the job.
        if shares < 0:
            return apology("Negative shares? You broke the financial industry!")

        # if 0, deletes that stock from the stocks table. Info still in transactions table.
        elif shares == 0:
            db.execute("DELETE FROM stocks WHERE user_id = :user_id AND symbol = :symbol",
                                user_id=session["user_id"],
                                symbol=request.form.get("symbol")
                                )

        # Subtracts shares from users' shares in "stocks".
        db.execute("UPDATE stocks SET shares = :shares WHERE user_id = :user_id AND symbol = :symbol",
                                shares=shares,
                                user_id=session["user_id"],
                                symbol=request.form.get("symbol")
                                )

        return redirect("/")

        """GET provides help info to the seller"""
    else:

        """look ups prices for symbols"""
        quoteds = []
        prices = []
        for symbol in symbols:  # symbol initialized at beginning of def
            quoteds.append(lookup(symbol))

        """separates stock prices into list var"""
        for quote in quoteds:
            prices.append(quote["price"])

        """"inserts prices into rows as key/value pair"""
        for row in rows:
            row["price"] = prices.pop(0)

        """averages prices on bought shares to show average gain/loss"""

        av_prices = []  # list of average prices/share buy history

        for symbol in symbols:
            prices = []
            shareses = 0  # say it in Gollum's voice. For counting total shares
            av_info = db.execute("SELECT price, shares FROM transactions WHERE user_id = :user_id AND symbol=:symbol AND shares > 0",
                                user_id=session["user_id"],
                                symbol=symbol
                                )

            for row in av_info:
                shareses = shareses + row["shares"]
                prices.append(row['price'] * row["shares"])
                av_price = sum(prices) / shareses
            av_prices.append(av_price)

        return render_template("sell.html", symbols=symbols,
                                rows=rows,
                                cash=cash,
                                av_prices=av_prices)

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
