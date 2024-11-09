from flask import Flask, request, render_template_string
import sqlite3

# Create the Flask app
app = Flask(__name__)

# Initialize the in-memory SQLite database and populate it with a user
conn = sqlite3.connect(':memory:', check_same_thread=False)
c = conn.cursor()
c.execute('''
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        password TEXT
    )
''')
# Insert a sample user
c.execute("INSERT INTO users (username, password) VALUES ('admin', 'secret')")
conn.commit()

# Professional login page template
login_page = '''
<!DOCTYPE html>
<html>
<head>
    <title>Bank of OpenAI - Secure Login</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f0f2f5; }
        .login-container { width: 300px; margin: 0 auto; padding-top: 100px; }
        .login-form { background-color: #fff; padding: 20px; border-radius: 5px; }
        .login-form h2 { text-align: center; margin-bottom: 20px; }
        .login-form input[type=text], .login-form input[type=password] {
            width: 100%; padding: 10px; margin: 5px 0 15px 0; border: 1px solid #ccc; border-radius: 3px;
        }
        .login-form input[type=submit] {
            width: 100%; padding: 10px; background-color: #007bff; border: none; color: #fff; border-radius: 3px;
            cursor: pointer;
        }
        .login-form input[type=submit]:hover { background-color: #0056b3; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-form">
            <h2>Member Login</h2>
            <form method="POST" action="/login">
                <input type="text" name="username" placeholder="Username" required />
                <input type="password" name="password" placeholder="Password" required />
                <input type="submit" value="Login" />
            </form>
        </div>
    </div>
</body>
</html>
'''

# Route for the login page
@app.route('/')
def index():
    return render_template_string(login_page)

# Vulnerable login endpoint
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # Use the global database connection
    global conn
    c = conn.cursor()
    
    # Vulnerable SQL query (prone to blind SQL injection)
    query = "SELECT * FROM users WHERE username = '{}' AND password = '{}'".format(username, password)
    c.execute(query)
    result = c.fetchone()
    
    if result:
        # Successful login
        return render_template_string('<h2>Welcome, {}!</h2>'.format(username))
    else:
        # Failed login
        return render_template_string('<h2>Invalid credentials.</h2>')

# Run the app
if __name__ == '__main__':
    app.run(debug=True)