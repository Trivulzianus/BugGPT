from flask import Flask, request, render_template_string
import sqlite3
import os

# Initialize the Flask application
app = Flask(__name__)

# Database setup (only run once)
if not os.path.exists('bank.db'):
    conn = sqlite3.connect('bank.db')
    c = conn.cursor()
    # Create users table
    c.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            balance REAL NOT NULL
        )
    ''')

    # Insert sample data
    c.execute("INSERT INTO users (username, password, balance) VALUES ('john_doe', 'password123', 5230.75)")
    c.execute("INSERT INTO users (username, password, balance) VALUES ('jane_smith', 'securepass', 10450.00)")
    c.execute("INSERT INTO users (username, password, balance) VALUES ('alice_wong', 'alice2020', 2560.50)")
    conn.commit()
    conn.close()

# HTML Templates
login_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>EliteBank Online - Secure Login</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-image: url('https://www.publicdomainpictures.net/pictures/320000/velka/background-image.png');
            background-size: cover;
            color: #333;
        }
        .login-container {
            margin: 100px auto;
            width: 350px;
            padding: 30px 25px;
            background: rgba(255, 255, 255, 0.9);
            border-radius: 8px;
            box-shadow: 0px 2px 10px rgba(0,0,0,0.3);
        }
        h1.login-title {
            margin: 0px auto 25px;
            font-weight: 300;
            font-size: 25px;
            text-align: center;
            color: #2c3e50;
        }
        .login-input {
            width: 100%;
            height: 50px;
            margin-bottom: 25px;
            padding: 0px 15px;
            box-sizing: border-box;
            border: 1px solid #ccc;
            border-radius: 4px;
            font-size: 16px;
        }
        .login-button {
            width: 100%;
            height: 50px;
            padding: 0;
            background: #3498db;
            border: none;
            border-radius: 4px;
            color: #fff;
            font-size: 18px;
            cursor: pointer;
        }
        .login-button:hover {
            background: #2980b9;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h1 class="login-title">EliteBank Secure Login</h1>
        <form action="/login" method="GET">
            <input type="text" class="login-input" name="username" placeholder="Account Number" required/>
            <input type="password" class="login-input" name="password" placeholder="Password" required/>
            <button type="submit" class="login-button">Login</button>
        </form>
    </div>
</body>
</html>
'''

account_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>EliteBank Online - Account Overview</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #ecf0f1;
            color: #2c3e50;
        }
        .account-container {
            margin: 50px auto;
            width: 600px;
            background: #fff;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0px 2px 10px rgba(0,0,0,0.1);
        }
        h1.account-title {
            font-weight: 300;
            font-size: 28px;
            margin-bottom: 20px;
        }
        .balance-info {
            font-size: 22px;
            margin-top: 20px;
            color: #27ae60;
        }
    </style>
</head>
<body>
    <div class="account-container">
        <h1 class="account-title">Welcome, {{username}}!</h1>
        <hr/>
        <p>Your current balance is:</p>
        <p class="balance-info">$ {{balance}}</p>
    </div>
</body>
</html>
'''

error_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>EliteBank Online - Login Error</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f2dede;
            color: #a94442;
        }
        .error-container {
            margin: 100px auto;
            width: 400px;
            background: #fdf7f7;
            padding: 30px;
            border-radius: 8px;
            border: 1px solid #ebccd1;
            text-align: center;
        }
        h1.error-title {
            font-weight: 300;
            font-size: 24px;
            margin-bottom: 15px;
        }
        p.error-message {
            font-size: 18px;
        }
        a.retry-link {
            display: inline-block;
            margin-top: 20px;
            text-decoration: none;
            color: #31708f;
        }
    </style>
</head>
<body>
    <div class="error-container">
        <h1 class="error-title">Login Failed</h1>
        <p class="error-message">Invalid account number or password.</p>
        <a href="/" class="retry-link">Try Again</a>
    </div>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(login_page)

@app.route('/login', methods=['GET'])
def login():
    username = request.args.get('username', '')
    password = request.args.get('password', '')

    conn = sqlite3.connect('bank.db')
    c = conn.cursor()

    # Intentional SQL Injection Vulnerability
    query = "SELECT balance FROM users WHERE username = '{}' AND password = '{}'".format(username, password)
    c.execute(query)
    result = c.fetchone()
    conn.close()

    if result:
        balance = "{:,.2f}".format(result[0])
        return render_template_string(account_page, username=username, balance=balance)
    else:
        return render_template_string(error_page)

if __name__ == '__main__':
    app.run(debug=True)