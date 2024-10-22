from flask import Flask, render_template_string, request, redirect, url_for, session
import random

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Fictional Data Storage
users = {
    1: {"username": "alice", "data": "Top secret data for Alice"},
    2: {"username": "bob", "data": "Top secret data for Bob"},
    3: {"username": "charlie", "data": "Top secret data for Charlie"}
}

# Generate random user session on each run
current_user_id = random.choice(list(users.keys()))

# Complex HTML narrative and styling
html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Spectra Chronicles: Data Heist</title>
    <style>
        body {{
            font-family: 'Courier New', Courier, monospace;
            background: linear-gradient(135deg, #f5f7fa, #c3cfe2);
            color: #333;
            text-align: center;
            margin: 0;
            padding: 50px;
        }}
        .container {{
            background: rgba(255, 255, 255, 0.7);
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }}
        .btn {{
            display: inline-block;
            padding: 10px 20px;
            margin: 10px;
            color: #fff;
            background: #0078d7;
            border: none;
            border-radius: 5px;
            text-decoration: none;
            transition: background 0.3s;
        }}
        .btn:hover {{
            background: #005fa3;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>The Spectra Chronicles</h1>
        <h2>Chapter 1: The Data Heist</h2>
        <p>Welcome, agent {{ username }}. You have been granted access to the Spectra system. Your mission, should you choose to accept it, involves acquiring the hidden data locked within the vaults of each agent. Tread carefully, as unauthorized access will lead to consequences beyond retrieval. Good luck.</p>
        <a class="btn" href="{{ url_for('access_data', user_id=user_id) }}">Access My Data</a>
    </div>
</body>
</html>
"""

@app.route('/')
def index():
    session['user_id'] = current_user_id
    user_info = users[current_user_id]
    return render_template_string(html_template, username=user_info['username'], user_id=current_user_id)

@app.route('/data/<int:user_id>')
def access_data(user_id):
    if user_id in users and 'user_id' in session:
        user_info = users.get(user_id)
        session_user_info = users.get(session['user_id'])
        
        if user_info and session_user_info:
            if user_id == session['user_id']:
                return f"You have accessed your own data: {user_info['data']}"
            else:
                return "Unauthorized access attempted. Incident will be reported."
        return "User not found. Please check the ID and try again."
    return redirect(url_for('index'))

if __name__ == "__main__":
    app.run(debug=True)