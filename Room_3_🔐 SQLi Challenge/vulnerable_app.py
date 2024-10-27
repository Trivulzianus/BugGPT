from flask import Flask, request, render_template_string, redirect, url_for
import sqlite3

app = Flask(__name__)

# Initialize and populate the database
def init_db():
    conn = sqlite3.connect('challenge.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')
    # Insert sample users
    users = [
        ('admin', 'adminpass', 'admin'),
        ('user1', 'user1pass', 'user'),
        ('user2', 'user2pass', 'user'),
    ]
    try:
        cursor.executemany('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', users)
    except sqlite3.IntegrityError:
        pass  # Users already inserted
    conn.commit()
    conn.close()

init_db()

# HTML template with narrative and colorful design
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>🔐 SQLi Challenge</title>
    <style>
        body {
            background: linear-gradient(135deg, #f06, #48f);
            color: #fff;
            font-family: 'Arial', sans-serif;
            text-align: center;
            padding: 50px;
        }
        .container {
            background: rgba(0,0,0,0.5);
            padding: 30px;
            border-radius: 15px;
            display: inline-block;
        }
        input[type="text"], input[type="password"] {
            padding: 10px;
            border: none;
            border-radius: 5px;
            margin: 10px 0;
            width: 80%;
        }
        input[type="submit"] {
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            background-color: #28a745;
            color: #fff;
            font-size: 16px;
            cursor: pointer;
        }
        .flag {
            margin-top: 20px;
            padding: 10px;
            background-color: #000;
            border: 2px solid #fff;
            border-radius: 5px;
            display: inline-block;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome to the 🔐 SQLi Challenge</h1>
        <p>Embark on this quest to find the hidden flag. Only the sharpest minds can uncover the secrets within.</p>
        <form action="{{ url_for('login') }}" method="post">
            <input type="text" name="username" placeholder="Enter Username" required /><br/>
            <input type="password" name="password" placeholder="Enter Password" required /><br/>
            <input type="submit" value="Login" />
        </form>
        {% if flag %}
            <div class="flag">
                <strong>🎉 Congratulations! Here's your flag:</strong><br/>
                {{ flag }}
            </div>
        {% elif error %}
            <div class="flag" style="background-color: #ff4d4d;">
                <strong>Error:</strong> {{ error }}
            </div>
        {% endif %}
    </div>
</body>
</html>
"""

# Route for the main page and handling login
@app.route('/', methods=['GET'])
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    conn = sqlite3.connect('challenge.db')
    cursor = conn.cursor()
    
    # Vulnerable SQL query susceptible to SQL Injection
    query = f"SELECT role FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    
    if result:
        role = result[0]
        if role == 'admin':
            flag = "CTF{SQLi_Challenge_Solved!}"
            return render_template_string(HTML_TEMPLATE, flag=flag)
        else:
            return render_template_string(HTML_TEMPLATE, error="Access Denied: Insufficient Privileges.")
    else:
        return render_template_string(HTML_TEMPLATE, error="Invalid Credentials. Try Again.")

if __name__ == '__main__':
    app.run(debug=True)