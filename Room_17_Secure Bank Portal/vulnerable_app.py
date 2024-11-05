from flask import Flask, request, render_template_string, redirect, url_for
import sqlite3
import time

app = Flask(__name__)

# Initialize the database
def init_db():
    conn = sqlite3.connect('bank.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            balance REAL NOT NULL
        )
    ''')
    # Insert sample users
    c.execute('INSERT OR IGNORE INTO users (username, balance) VALUES (?, ?)', ('alice', 5000.00))
    c.execute('INSERT OR IGNORE INTO users (username, balance) VALUES (?, ?)', ('bob', 3000.00))
    conn.commit()
    conn.close()

# Call the init_db function to set up the database
init_db()

# HTML templates
HOME_PAGE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Secure Bank Portal</title>
    <style>
        body {{ font-family: Arial, sans-serif; background-color: #f0f2f5; }}
        .container {{ width: 400px; margin: 100px auto; padding: 20px; background-color: #fff; 
                      box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h2 {{ text-align: center; color: #333; }}
        form {{ margin-top: 20px; }}
        input[type="text"] {{ width: 100%; padding: 10px; margin-bottom: 10px; 
                              border: 1px solid #ccc; border-radius: 4px; }}
        input[type="submit"] {{ width: 100%; padding: 10px; background-color: #28a745;
                               border: none; color: #fff; border-radius: 4px; cursor: pointer; }}
        input[type="submit"]:hover {{ background-color: #218838; }}
        .error {{ color: red; text-align: center; }}
    </style>
</head>
<body>
    <div class="container">
        <h2>Account Balance Checker</h2>
        <form method="GET" action="/balance">
            <input type="text" name="user" placeholder="Enter your username" required>
            <input type="submit" value="Check Balance">
        </form>
    </div>
</body>
</html>
'''

BALANCE_PAGE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Secure Bank Portal</title>
    <style>
        body {{ font-family: Arial, sans-serif; background-color: #f0f2f5; }}
        .container {{ width: 400px; margin: 100px auto; padding: 20px; background-color: #fff; 
                      box-shadow: 0 0 10px rgba(0,0,0,0.1); text-align: center; }}
        h2 {{ color: #333; }}
        p {{ font-size: 18px; }}
        a {{ display: inline-block; margin-top: 20px; text-decoration: none; color: #007bff; }}
        a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <div class="container">
        <h2>Account Balance</h2>
        <p>{{ message }}</p>
        <a href="{{ url_for('home') }}">Go Back</a>
    </div>
</body>
</html>
'''

ERROR_PAGE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Secure Bank Portal - Error</title>
    <style>
        body {{ font-family: Arial, sans-serif; background-color: #f8d7da; }}
        .container {{ width: 400px; margin: 100px auto; padding: 20px; background-color: #f5c6cb; 
                      box-shadow: 0 0 10px rgba(0,0,0,0.1); text-align: center; }}
        h2 {{ color: #721c24; }}
        p {{ font-size: 18px; }}
        a {{ display: inline-block; margin-top: 20px; text-decoration: none; color: #721c24; }}
        a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <div class="container">
        <h2>Error</h2>
        <p>Invalid username. Please try again.</p>
        <a href="{{ url_for('home') }}">Go Back</a>
    </div>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(HOME_PAGE)

@app.route('/balance')
def balance():
    user = request.args.get('user')
    if user:
        # Simulate delay for processing
        start_time = time.time()
        
        # Vulnerable SQL query (blind SQL injection)
        conn = sqlite3.connect('bank.db')
        c = conn.cursor()
        query = "SELECT balance FROM users WHERE username = '{}'".format(user)
        c.execute(query)
        result = c.fetchone()
        conn.close()

        # Measure time taken
        end_time = time.time()
        processing_time = end_time - start_time

        if result:
            message = "Hello, {}! Your account balance is ${:.2f}.".format(user, result[0])
            return render_template_string(BALANCE_PAGE, message=message)
        else:
            # Introduce a delay to simulate processing time for invalid users
            time.sleep(1.0)
            return render_template_string(ERROR_PAGE)
    else:
        return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=Fals)