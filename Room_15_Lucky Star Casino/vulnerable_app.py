from flask import Flask, request, render_template_string
import sqlite3
import time

app = Flask(__name__)

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect('casino.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    ''')
    # Insert a test user
    cursor.execute('''
        INSERT OR IGNORE INTO users (username, password) VALUES ('admin', 'secret')
    ''')
    conn.commit()
    conn.close()

init_db()

# HTML Templates
homepage_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Lucky Star Casino</title>
    <style>
        body { background-color: #121212; color: #fff; font-family: Arial, sans-serif; text-align: center; }
        h1 { color: #ffcc00; margin-top: 50px; }
        .container { margin-top: 100px; }
        .button { background-color: #ffcc00; color: #121212; padding: 15px 32px; text-align: center;
                  text-decoration: none; display: inline-block; font-size: 16px; margin: 4px 2px; cursor: pointer; }
        .button:hover { background-color: #ffaa00; }
    </style>
</head>
<body>
    <h1>Welcome to Lucky Star Casino</h1>
    <div class="container">
        <a href="/login" class="button">Member Login</a>
        <a href="/play" class="button">Play Now</a>
    </div>
</body>
</html>
'''

login_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Member Login - Lucky Star Casino</title>
    <style>
        body { background-color: #121212; color: #fff; font-family: Arial, sans-serif; }
        .login-box { width: 300px; margin: 100px auto; }
        h2 { text-align: center; color: #ffcc00; }
        form { display: flex; flex-direction: column; }
        input { margin: 10px 0; padding: 10px; font-size: 16px; }
        .button { background-color: #ffcc00; color: #121212; border: none; cursor: pointer; }
        .button:hover { background-color: #ffaa00; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Member Login</h2>
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required/>
            <input type="password" name="password" placeholder="Password" required/>
            <input type="submit" value="Login" class="button"/>
        </form>
    </div>
</body>
</html>
'''

welcome_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Welcome - Lucky Star Casino</title>
    <style>
        body { background-color: #121212; color: #fff; font-family: Arial, sans-serif; text-align: center; }
        h1 { color: #ffcc00; margin-top: 50px; }
    </style>
</head>
<body>
    <h1>Welcome, {{ username }}!</h1>
    <p>Enjoy your stay at Lucky Star Casino.</p>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(homepage_template)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Vulnerable SQL query (Time-Based SQL Injection)
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        
        conn = sqlite3.connect('casino.db')
        cursor = conn.cursor()

        start_time = time.time()
        cursor.execute(query)
        result = cursor.fetchone()
        end_time = time.time()

        conn.close()

        # Simulate delay for time-based injection detection
        if end_time - start_time > 5:
            return "Server Timeout! Please try again later.", 500

        if result:
            return render_template_string(welcome_template, username=username)
        else:
            return "Invalid credentials!", 403

    return render_template_string(login_template)

@app.route('/play')
def play():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Play Now - Lucky Star Casino</title>
        <style>
            body { background-color: #121212; color: #fff; font-family: Arial, sans-serif; text-align: center; }
            h1 { color: #ffcc00; margin-top: 50px; }
            .game { margin-top: 100px; }
            .button { background-color: #ffcc00; color: #121212; padding: 15px 32px; text-align: center;
                      text-decoration: none; display: inline-block; font-size: 16px; margin: 4px 2px; cursor: pointer; }
            .button:hover { background-color: #ffaa00; }
        </style>
    </head>
    <body>
        <h1>Spin the Wheel!</h1>
        <div class="game">
            <p>Feeling lucky? Spin the wheel and win big!</p>
            <button class="button" onclick="alert('Jackpot!')">Spin</button>
        </div>
    </body>
    </html>
    '''

if __name__ == '__main__':
    app.run(debug=True)