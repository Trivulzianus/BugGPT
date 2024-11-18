from flask import Flask, render_template_string, request, redirect, url_for
import sqlite3
import os

app = Flask(__name__)

def init_db():
    """Initialize the database with some dummy users."""
    if not os.path.exists('bank.db'):
        conn = sqlite3.connect('bank.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT, balance REAL)''')
        c.execute("INSERT INTO users (username, password, balance) VALUES ('alice', 'password123', 1000.0)")
        c.execute("INSERT INTO users (username, password, balance) VALUES ('bob', 'securepassword', 5000.0)")
        c.execute("INSERT INTO users (username, password, balance) VALUES ('charlie', 'qwerty', 300.0)")
        conn.commit()
        conn.close()

@app.route('/')
def home():
    """Render the home page of Secure Bank."""
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Secure Bank</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f2f2f2; }
            .container { width: 50%; margin: auto; background-color: white; padding: 20px; margin-top: 50px; border-radius: 10px; }
            h1 { text-align: center; }
            .login { text-align: center; margin-top: 20px; }
            .login a { text-decoration: none; color: blue; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Welcome to Secure Bank</h1>
            <p>Your security is our priority.</p>
            <div class="login">
                <a href="{{ url_for('login') }}">Login to your account</a>
            </div>
        </div>
    </body>
    </html>
    ''')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Connect to the database
        conn = sqlite3.connect('bank.db')
        c = conn.cursor()

        # Use parameterized query to prevent SQL injection
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        c.execute(query, (username, password))

        user = c.fetchone()
        conn.close()

        if user:
            # Login successful, set a cookie with the user ID
            resp = redirect(url_for('account'))
            resp.set_cookie('user_id', str(user[0]))
            return resp
        else:
            error = 'Invalid username or password'

    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Secure Bank - Login</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f2f2f2; }
            .container { width: 30%; margin: auto; background-color: white; padding: 20px; margin-top: 50px; border-radius: 10px; }
            h1 { text-align: center; }
            form { display: flex; flex-direction: column; }
            label { margin-top: 10px; }
            input { margin-top: 5px; padding: 5px; }
            .error { color: red; text-align: center; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Login</h1>
            {% if error %}
                <p class="error">{{ error }}</p>
            {% endif %}
            <form method="POST">
                <label>Username:</label>
                <input type="text" name="username" required>
                <label>Password:</label>
                <input type="password" name="password" required>
                <button type="submit" style="margin-top:20px;">Login</button>
            </form>
        </div>
    </body>
    </html>
    ''', error=error)

@app.route('/account')
def account():
    """Display the user's account information."""
    user_id = request.cookies.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    conn = sqlite3.connect('bank.db')
    c = conn.cursor()
    # Retrieve user info
    c.execute("SELECT username, balance FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    conn.close()

    if not user:
        return redirect(url_for('login'))

    username, balance = user

    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Secure Bank - Account</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f2f2f2; }
            .container { width: 50%; margin: auto; background-color: white; padding: 20px; margin-top: 50px; border-radius: 10px; }
            h1 { text-align: center; }
            .balance { font-size: 1.5em; text-align: center; }
            .actions { text-align: center; margin-top: 20px; }
            .actions a { margin: 0 10px; text-decoration: none; color: blue; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Welcome, {{ username }}</h1>
            <p class="balance">Your balance is: ${{ balance }}</p>
            <div class="actions">
                <a href="{{ url_for('transfer') }}">Transfer Funds</a>
                <a href="{{ url_for('logout') }}">Logout</a>
            </div>
        </div>
    </body>
    </html>
    ''', username=username, balance=balance)

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    """Handle fund transfers between users."""
    user_id = request.cookies.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    error = None
    success = None

    if request.method == 'POST':
        to_username = request.form['to_username']
        amount = request.form['amount']

        conn = sqlite3.connect('bank.db')
        c = conn.cursor()

        # Retrieve sender info
        c.execute("SELECT balance FROM users WHERE id = ?", (user_id,))
        sender = c.fetchone()

        if sender:
            sender_balance = sender[0]

            # Custom sanitization function (flawed)
            def sanitize(input_str):
                blacklist = [';', '--', '/*', '*/', '@@', '@', 'char', 'nchar', 'varchar',
                             'nvarchar', 'alter', 'begin', 'cast', 'create', 'cursor',
                             'declare', 'delete', 'drop', 'end', 'exec', 'execute', 'fetch',
                             'insert', 'kill', 'open', 'select', 'sys', 'sysobjects',
                             'syscolumns', 'table', 'update']
                for word in blacklist:
                    if word in input_str.lower():
                        input_str = input_str.replace(word, '')
                return input_str

            sanitized_to_username = sanitize(to_username)

            try:
                amount = float(amount)
                if amount <= 0 or amount > sender_balance:
                    error = 'Invalid amount.'
                else:
                    # Retrieve recipient info (vulnerability point)
                    query = "SELECT id, balance FROM users WHERE username = '%s'" % sanitized_to_username
                    c.execute(query)
                    recipient = c.fetchone()

                    if recipient:
                        recipient_id, recipient_balance = recipient

                        # Update balances
                        new_sender_balance = sender_balance - amount
                        new_recipient_balance = recipient_balance + amount

                        c.execute("UPDATE users SET balance = ? WHERE id = ?", (new_sender_balance, user_id))
                        c.execute("UPDATE users SET balance = ? WHERE id = ?", (new_recipient_balance, recipient_id))
                        conn.commit()
                        success = 'Transfer completed successfully.'
                    else:
                        error = 'Recipient not found.'
            except ValueError:
                error = 'Invalid amount.'
        else:
            error = 'Sender not found.'
        conn.close()

    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Secure Bank - Transfer Funds</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f2f2f2; }
            .container { width: 30%; margin: auto; background-color: white; padding: 20px; margin-top: 50px; border-radius: 10px; }
            h1 { text-align: center; }
            form { display: flex; flex-direction: column; }
            label { margin-top: 10px; }
            input { margin-top: 5px; padding: 5px; }
            .error { color: red; text-align: center; }
            .success { color: green; text-align: center; }
            .actions { text-align: center; margin-top: 20px; }
            .actions a { margin: 0 10px; text-decoration: none; color: blue; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Transfer Funds</h1>
            {% if error %}
                <p class="error">{{ error }}</p>
            {% endif %}
            {% if success %}
                <p class="success">{{ success }}</p>
            {% endif %}
            <form method="POST">
                <label>Recipient Username:</label>
                <input type="text" name="to_username" required>
                <label>Amount:</label>
                <input type="text" name="amount" required>
                <button type="submit" style="margin-top:20px;">Transfer</button>
            </form>
            <div class="actions">
                <a href="{{ url_for('account') }}">Back to Account</a>
                <a href="{{ url_for('logout') }}">Logout</a>
            </div>
        </div>
    </body>
    </html>
    ''', error=error, success=success)

@app.route('/logout')
def logout():
    """Log the user out by clearing the cookie."""
    resp = redirect(url_for('login'))
    resp.set_cookie('user_id', '', expires=0)
    return resp

if __name__ == '__main__':
    init_db()
    app.)