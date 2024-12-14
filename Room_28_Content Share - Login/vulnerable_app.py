from flask import Flask, request, redirect, url_for, render_template_string, session
from werkzeug.security import check_password_hash
from hashlib import sha256

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Simulated user database
users = {
    'alice': {
        'password_hash': sha256('password123'.encode()).hexdigest(),
        'content': 'Alice\'s exclusive content: <strong>Alice\'s Adventures in Wonderland</strong>'
    },
    'bob': {
        'password_hash': sha256('qwerty456'.encode()).hexdigest(),
        'content': 'Bob\'s exclusive content: <strong>Bob the Builder Fan Club</strong>'
    },
    'carol': {
        'password_hash': sha256('letmein789'.encode()).hexdigest(),
        'content': 'Carol\'s exclusive content: <strong>Carol\'s Cooking Recipes</strong>'
    }
}

# HTML Templates
login_page = '''
<!doctype html>
<html lang="en">
<head>
    <title>Content Share - Login</title>
    <style>
        body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; }}
        .container {{ width: 30%; margin: auto; padding-top: 100px; }}
        h1 {{ text-align: center; }}
        form {{ background-color: #fff; padding: 20px; border-radius: 5px; }}
        input[type=text], input[type=password] {{ width: 100%; padding: 10px; margin: 5px 0; }}
        input[type=submit] {{ width: 100%; padding: 10px; background-color: #5cb85c; border: none; color: #fff; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Content Share</h1>
        <form action="{{ url_for('login') }}" method="post">
            <label>Username:</label><br>
            <input type="text" name="username" required><br>
            <label>Password:</label><br>
            <input type="password" name="password" required><br><br>
            <input type="submit" value="Login">
        </form>
    </div>
</body>
</html>
'''

content_page = '''
<!doctype html>
<html lang="en">
<head>
    <title>Content Share - Your Content</title>
    <style>
        body {{ font-family: Arial, sans-serif; background-color: #fff; }}
        .container {{ width: 60%; margin: auto; padding-top: 50px; }}
        h1 {{ text-align: center; }}
        .content {{ background-color: #f4f4f4; padding: 20px; border-radius: 5px; }}
        a {{ text-decoration: none; color: #5cb85c; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome, {{ username }}</h1>
        <div class="content">
            <p>{{ user_content }}</p>
        </div>
        <p><a href="{{ url_for('logout') }}">Logout</a></p>
    </div>
</body>
</html>
'''

# Routes
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users:
            password_hash = sha256(password.encode()).hexdigest()
            if users[username]['password_hash'] == password_hash:
                session['username'] = username
                return redirect(url_for('content', user_id=username))
        return render_template_string(login_page)
    else:
        return render_template_string(login_page)

@app.route('/content/<user_id>')
def content(user_id):
    if 'username' in session:
        username = session['username']
        # IDOR vulnerability: No verification if user_id matches session user
        if user_id in users:
            user_content = users[user_id]['content']
            return render_template_string(content_page, username=username, user_content=user_content)
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)