from flask import Flask, render_template, request
import sqlite3
import time
import os

app = Flask(__name__)

# Initialize the database connection and create tables
def init_db():
    conn = sqlite3.connect('bank.db')
    cursor = conn.cursor()
    # Create a sample users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT
        )
    ''')
    # Insert sample data
    cursor.execute('DELETE FROM users')  # Clear existing data
    cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('alice', 'wonderland'))
    cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('bob', 'builder'))
    conn.commit()
    conn.close()

# Ensure the templates directory exists
if not os.path.exists('templates'):
    os.makedirs('templates')

# Write the login.html template
with open('templates/login.html', 'w') as f:
    f.write('''
<!DOCTYPE html>
<html>
<head>
    <title>Secure Bank Login</title>
    <style>
        /* Add some styling to make it look professional */
        body {
            font-family: Arial, sans-serif;
            background-color: #f2f2f2;
        }
        .login-container {
            margin: 50px auto;
            width: 300px;
            padding: 20px;
            background-color: #ffffff;
            border: 1px solid #dddddd;
            border-radius: 5px;
        }
        h2 {
            text-align: center;
        }
        input[type=text], input[type=password] {
            width: 100%;
            padding: 8px 12px;
            margin: 8px 0;
            display: inline-block;
            border: 1px solid #cccccc;
            border-radius: 4px;
            box-sizing: border-box;
        }
        .error {
            color: red;
            text-align: center;
        }
        .response-time {
            color: gray;
            text-align: center;
            font-size: 0.8em;
        }
        input[type=submit] {
            width: 100%;
            background-color: #4CAF50;
            color: white;
            padding: 10px 15px;
            margin: 8px 0;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        .bank-logo {
            width: 100%;
            text-align: center;
            margin-bottom: 20px;
        }
        .bank-logo img {
            width: 150px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="bank-logo">
            <img src="https://via.placeholder.com/150?text=Bank+Logo" alt="Bank Logo">
        </div>
        <h2>Secure Bank Login</h2>
        {% if error %}
            <p class="error">{{ error }}</p>
        {% endif %}
        {% if response_time %}
            <p class="response-time">Response Time: {{ response_time }} seconds</p>
        {% endif %}
        <form action="/login" method="post">
            <label for="username">Username</label>
            <input type="text" id="username" name="username" required>
            <!-- Assuming we're only using username for this test -->
            <!-- <label for="password">Password</label>
            <input type="password" id="password" name="password" required> -->
            <input type="submit" value="Login">
        </form>
    </div>
</body>
</html>
    ''')

# Write the welcome.html template
with open('templates/welcome.html', 'w') as f:
    f.write('''
<!DOCTYPE html>
<html>
<head>
    <title>Welcome to Secure Bank</title>
    <style>
        /* Styling for the welcome page */
        body {
            font-family: Arial, sans-serif;
            background-color: #f2f2f2;
        }
        .welcome-container {
            margin: 50px auto;
            width: 400px;
            padding: 20px;
            background-color: #ffffff;
            border: 1px solid #dddddd;
            border-radius: 5px;
            text-align: center;
        }
        .bank-logo {
            width: 100%;
            text-align: center;
            margin-bottom: 20px;
        }
        .bank-logo img {
            width: 150px;
        }
        h2 {
            color: #4CAF50;
        }
    </style>
</head>
<body>
    <div class="welcome-container">
        <div class="bank-logo">
            <img src="https://via.placeholder.com/150?text=Bank+Logo" alt="Bank Logo">
        </div>
        <h2>Welcome, {{ username }}!</h2>
        <p>Your account dashboard is under construction.</p>
    </div>
</body>
</html>
    ''')

# Define the home route
@app.route('/')
def index():
    return render_template('login.html')

# Define the login route with vulnerability
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    # Vulnerable SQL query (not using parameterized queries)
    conn = sqlite3.connect('bank.db')
    # Create the sleep function
    conn.create_function("sleep", 1, time.sleep)
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    start_time = time.time()
    try:
        cursor.execute(query)
        results = cursor.fetchall()
    except Exception as e:
        # If there's an error, e.g., due to SQL injection syntax, treat it as invalid
        results = []
    elapsed_time = time.time() - start_time
    conn.close()
    if results:
        return render_template('welcome.html', username=username)
    else:
        return render_template('login.html', error='Invalid username', response_time="{0:.2f}".format(elapsed_time))

if __name__ == '__main__':
    init_db()
    app.)