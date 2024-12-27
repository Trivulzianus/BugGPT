from flask import Flask, request, render_template_string, session, redirect, url_for
import sqlite3
import time
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Initialize the database with sample data
def init_db():
    conn = sqlite3.connect('casino.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            balance INTEGER NOT NULL
        )
    ''')
    conn.commit()
    c.execute('DELETE FROM users')  # Clear existing data
    # Insert sample users
    c.executemany('INSERT INTO users (username, password, balance) VALUES (?, ?, ?)', [
        ('john_doe', 'password123', 5000),
        ('jane_smith', 'qwerty', 7500),
        ('lucky_player', 'jackpot', 10000)
    ])
    conn.commit()
    conn.close()

# Define a custom sleep function for SQLite
def sqlite_sleep(seconds):
    time.sleep(seconds)

init_db()

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Royal Flush Casino</title>
        <style>
            body { background: url('https://example.com/casino-background.jpg'); color: #fff; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
            .container { text-align: center; padding-top: 100px; }
            .login-form { background: rgba(0, 0, 0, 0.7); display: inline-block; padding: 20px; border-radius: 10px; }
            input[type=text], input[type=password] { width: 250px; padding: 10px; margin: 5px 0; border: none; border-radius: 5px; }
            input[type=submit] { padding: 10px 20px; border: none; border-radius: 5px; background-color: #e67e22; color: #fff; font-size: 16px; cursor: pointer; }
            input[type=submit]:hover { background-color: #d35400; }
            h1 { font-size: 48px; }
            .message { font-size: 18px; color: #e74c3c; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Royal Flush Casino</h1>
            <div class="login-form">
                <form action="/login" method="post">
                    <div>
                        <input type="text" name="username" placeholder="Username" required />
                    </div>
                    <div>
                        <input type="password" name="password" placeholder="Password" required />
                    </div>
                    <div>
                        <input type="submit" value="Login" />
                    </div>
                </form>
            </div>
            {% if message %}
            <div class="message">{{ message }}</div>
            {% endif %}
        </div>
    </body>
    </html>
    ''')

@app.route('/login', methods=['POST'])
def login():
    username_input = request.form.get('username', '')
    password_input = request.form.get('password', '')
    # Complex query with potential for time-based SQLi
    query = """
    SELECT * FROM users WHERE username = '{}' AND password = '{}'
    """.format(username_input, password_input)
    # Connect to the database
    conn = sqlite3.connect('casino.db')
    conn.create_function('sleep', 1, sqlite_sleep)  # Register custom sleep function
    c = conn.cursor()
    try:
        c.execute(query)
        user = c.fetchone()
        conn.close()
        if user:
            session['username'] = user[1]
            return redirect(url_for('dashboard'))
        else:
            return render_template_string('''
            {% extends "index" %}
            {% block message %}
            Invalid username or password.
            {% endblock %}
            ''')
    except Exception as e:
        conn.close()
        return render_template_string('''
        {% extends "index" %}
        {% block message %}
        An unexpected error occurred. Please try again later.
        {% endblock %}
        ''')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('index'))
    username = session['username']
    # Fetch user balance securely
    conn = sqlite3.connect('casino.db')
    c = conn.cursor()
    c.execute("SELECT balance FROM users WHERE username = ?", (username,))
    balance = c.fetchone()[0]
    conn.close()
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>{{ username }}'s Dashboard - Royal Flush Casino</title>
        <style>
            body { background: #34495e; color: #ecf0f1; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
            .container { text-align: center; padding-top: 50px; }
            .balance { font-size: 24px; margin-top: 20px; }
            .nav { margin-top: 30px; }
            .nav a { color: #1abc9c; text-decoration: none; margin: 0 10px; font-size: 18px; }
            .nav a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Welcome, {{ username }}!</h1>
            <div class="balance">
                Current Balance: ${{ balance }}
            </div>
            <div class="nav">
                <a href="/play">Play Games</a>
                <a href="/logout">Logout</a>
            </div>
        </div>
    </body>
    </html>
    ''', username=username, balance=balance)

@app.route('/play')
def play():
    if 'username' not in session:
        return redirect(url_for('index'))
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Play Games - Royal Flush Casino</title>
        <style>
            body { background: #8e44ad; color: #fff; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
            .container { text-align: center; padding-top: 100px; }
            .games { margin-top: 50px; }
            .games a { display: inline-block; background: #3498db; color: #fff; padding: 15px 30px; margin: 10px; text-decoration: none; border-radius: 5px; }
            .games a:hover { background: #2980b9; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Select a Game to Play</h1>
            <div class="games">
                <a href="#">Blackjack</a>
                <a href="#">Roulette</a>
                <a href="#">Slots</a>
                <a href="#">Poker</a>
            </div>
            <div class="nav">
                <a href="/dashboard" style="color: #ecf0f1; text-decoration: none;">Back to Dashboard</a>
            </div>
        </div>
    </body>
    </html>
    ''')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)