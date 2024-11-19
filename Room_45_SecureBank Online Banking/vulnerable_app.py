from flask import Flask, render_template_string, request
import sqlite3

app = Flask(__name__)

# Initialize the database
database = 'securebank.db'

def init_db():
    conn = sqlite3.connect(database)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            balance REAL NOT NULL
        )
    ''')
    # Seed with sample data
    c.execute("INSERT OR IGNORE INTO users (username, password, balance) VALUES ('john_doe', 'password123', 1500.75)")
    c.execute("INSERT OR IGNORE INTO users (username, password, balance) VALUES ('jane_smith', 'mypassword', 2450.60)")
    conn.commit()
    conn.close()

init_db()

# HTML Templates
login_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>SecureBank Online Banking</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #e9edf0; }
        .container { width: 400px; margin: 100px auto; }
        h2 { text-align: center; color: #2c3e50; }
        form { background-color: #fff; padding: 30px; border-radius: 10px; box-shadow: 0px 0px 10px #aaa; }
        input[type=text], input[type=password] {
            width: 100%; padding: 12px 20px; margin: 8px 0;
            display: inline-block; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box;
        }
        input[type=submit] {
            width: 100%; background-color: #2980b9; color: white;
            padding: 14px 20px; margin: 8px 0; border: none; border-radius: 4px;
            cursor: pointer; font-size: 16px;
        }
        input[type=submit]:hover { background-color: #21618c; }
        .error { color: red; text-align: center; }
        .footer { text-align: center; margin-top: 20px; color: #7f8c8d; }
    </style>
</head>
<body>
    <div class="container">
        <h2>SecureBank Login</h2>
        {% if error %}
        <p class="error">{{ error }}</p>
        {% endif %}
        <form method="post">
            <label for="username">Username</label>
            <input type="text" id="username" name="username" placeholder="Enter your username" required>

            <label for="password">Password</label>
            <input type="password" id="password" name="password" placeholder="Enter your password" required>

            <input type="submit" value="Login">
        </form>
        <div class="footer">
            &copy; 2023 SecureBank Inc. All rights reserved.
        </div>
    </div>
</body>
</html>
'''

dashboard_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>SecureBank Account Dashboard</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #e9edf0; }
        .container { width: 600px; margin: 50px auto; }
        h2 { text-align: center; color: #2c3e50; }
        .account-info {
            background-color: #fff; padding: 30px; border-radius: 10px;
            box-shadow: 0px 0px 10px #aaa; text-align: center;
        }
        .account-info h3 { color: #2980b9; }
        .account-info p { font-size: 18px; }
        .logout { margin-top: 20px; }
        .logout a {
            color: #2980b9; text-decoration: none; font-size: 16px;
        }
        .logout a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Welcome to SecureBank, {{ username }}!</h2>
        <div class="account-info">
            <h3>Account Summary</h3>
            <p>Account Balance: <strong>${{ balance }}</strong></p>
            <p>Account Number: **** **** **** 1234</p>
            <p>Last Login: October 15, 2023</p>
        </div>
        <div class="logout">
            <a href="/">Logout</a>
        </div>
    </div>
</body>
</html>
'''

@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # SQL Injection Vulnerability
        conn = sqlite3.connect(database)
        c = conn.cursor()
        query = "SELECT * FROM users WHERE username = '{}' AND password = '{}'".format(username, password)
        c.execute(query)
        user = c.fetchone()
        conn.close()

        if user:
            return render_template_string(dashboard_template, username=user[1], balance=user[3])
        else:
            error = 'Invalid credentials. Please try again.'

    return render_template_string(login_template, error=error)

if __name__ == '__main__':
    app.run(debug=True)