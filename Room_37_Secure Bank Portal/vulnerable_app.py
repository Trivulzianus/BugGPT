from flask import Flask, render_template, request, redirect, url_for, session, g
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'

DATABASE = 'bank.db'

def get_db():
    """Establish a connection to the database."""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    """Close the database connection at the end of the request."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """Initialize the database with tables and sample data."""
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                account_id INTEGER NOT NULL
            )
        ''')
        # Create accounts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS accounts(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_number TEXT UNIQUE NOT NULL,
                balance REAL NOT NULL
            )
        ''')
        # Insert sample accounts
        accounts = [
            ('ACC1001', 5000.00),
            ('ACC1002', 7500.50),
            ('ACC1003', 6200.75),
        ]
        cursor.executemany('''
            INSERT OR IGNORE INTO accounts(account_number, balance)
            VALUES(?, ?)
        ''', accounts)
        # Insert sample users with hashed passwords
        users = [
            ('alice', generate_password_hash('password123'), 1),
            ('bob', generate_password_hash('securepass'), 2),
            ('charlie', generate_password_hash('charlie2023'), 3),
        ]
        cursor.executemany('''
            INSERT OR IGNORE INTO users(username, password, account_id)
            VALUES(?, ?, ?)
        ''', users)
        db.commit()

def create_templates():
    """Create HTML templates and static files for the web app."""
    if not os.path.exists('templates'):
        os.makedirs('templates')
    if not os.path.exists('static'):
        os.makedirs('static')

    # index.html
    with open('templates/index.html', 'w') as f:
        f.write('''<!DOCTYPE html>
<html>
<head>
    <title>Secure Bank Portal</title>
    <link rel="stylesheet" type="text/css" href="{{url_for('static', filename='style.css')}}">
</head>
<body>
    <h1>Welcome to Secure Bank</h1>
    <p>Your trusted partner in online banking.</p>
    {% if 'user_id' in session %}
        <p>Hello, {{session['username']}}!</p>
        <a href="{{url_for('dashboard')}}">Go to Dashboard</a> | <a href="{{url_for('logout')}}">Logout</a>
    {% else %}
        <a href="{{url_for('login')}}">Login</a>
    {% endif %}
</body>
</html>
''')

    # login.html
    with open('templates/login.html', 'w') as f:
        f.write('''<!DOCTYPE html>
<html>
<head>
    <title>Login - Secure Bank</title>
    <link rel="stylesheet" type="text/css" href="{{url_for('static', filename='style.css')}}">
</head>
<body>
    <h1>Login to Secure Bank</h1>
    {% if error %}
        <p style="color:red;">{{error}}</p>
    {% endif %}
    <form method="post">
        <label>Username:</label><br>
        <input type="text" name="username"><br><br>
        <label>Password:</label><br>
        <input type="password" name="password"><br><br>
        <input type="submit" value="Login">
    </form>
</body>
</html>
''')

    # account.html
    with open('templates/account.html', 'w') as f:
        f.write('''<!DOCTYPE html>
<html>
<head>
    <title>Account Details - Secure Bank</title>
    <link rel="stylesheet" type="text/css" href="{{url_for('static', filename='style.css')}}">
</head>
<body>
    <h1>Account Details</h1>
    <p>Account Number: {{account[1]}}</p>
    <p>Balance: ${{account[2]}}</p>
    <a href="{{url_for('logout')}}">Logout</a>
</body>
</html>
''')

    # style.css
    with open('static/style.css', 'w') as f:
        f.write('''body {
    font-family: Arial, sans-serif;
    background-color: #f0f2f5;
    text-align: center;
}
h1 {
    color: #333;
}
form {
    display: inline-block;
    margin-top: 20px;
    text-align: left;
}
input[type="text"], input[type="password"] {
    width: 200px;
    padding: 5px;
}
input[type="submit"] {
    padding: 5px 10px;
}
a {
    margin: 0 10px;
}
''')

@app.route('/')
def index():
    """Render the home page."""
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid username or password.'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    """Log the user out and clear the session."""
    session.clear()
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    """Redirect the user to their account details page."""
    if 'user_id' in session:
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT account_id FROM users WHERE id = ?', (session['user_id'],))
        account_id = cursor.fetchone()[0]
        # Redirect to the account details page with the account ID
        return redirect(url_for('account_details', account_id=account_id))
    else:
        return redirect(url_for('login'))

@app.route('/account/<int:account_id>')
def account_details(account_id):
    """Display account details (vulnerable to IDOR)."""
    if 'user_id' in session:
        db = get_db()
        cursor = db.cursor()
        # Vulnerable: Does not verify if the account belongs to the logged-in user
        cursor.execute('SELECT * FROM accounts WHERE id = ?', (account_id,))
        account = cursor.fetchone()
        if account:
            return render_template('account.html', account=account)
        else:
            return 'Account not found.', 404
    else:
        return redirect(url_for('login'))

if __name__ == '__main__':
    # Set up the templ)