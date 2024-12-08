from flask import Flask, render_template_string, request, redirect, url_for, session
from urllib.parse import urlparse, urljoin
import requests

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Simulated database of users
users = {
    'alice': {'password': 'password123', 'avatar': '/static/avatars/default.png'},
    'bob': {'password': 'qwerty', 'avatar': '/static/avatars/default.png'},
}

# Forum posts
posts = [
    {'author': 'alice', 'content': 'Hello, this is my first post!'},
    {'author': 'bob', 'content': 'Welcome to the forum, Alice!'}
]

# Home page
@app.route('/')
def home():
    return render_template_string('''
    <!doctype html>
    <html>
    <head>
        <title>SecureForum - Home</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f4f4f4; }
            .container { width: 80%; margin: auto; overflow: hidden; }
            header { background: #50b3a2; color: #fff; padding-top: 30px; min-height: 70px; border-bottom: #e8491d 3px solid; }
            header a { color: #fff; text-decoration: none; text-transform: uppercase; font-size: 16px; }
            header ul { margin: 0; padding: 0; }
            header li { float: left; display: inline; padding: 0 20px 0 20px; }
            header #branding { float: left; }
            header #branding h1 { margin: 0; }
            header nav { float: right; margin-top: 10px; }
            #posts { margin-top: 30px; background: #fff; padding: 20px; }
            #posts h2 { margin-top: 0; }
            .post { border-bottom: 1px #ccc dotted; padding-bottom: 10px; margin-bottom: 10px; }
            .post:last-child { border: none; }
            footer { background: #50b3a2; color: #fff; text-align: center; padding: 20px; margin-top: 20px; }
            .avatar { width: 50px; height: 50px; border-radius: 50%; vertical-align: middle; }
        </style>
    </head>
    <body>
        <header>
            <div class="container">
                <div id="branding">
                    <h1><a href="/">SecureForum</a></h1>
                </div>
                <nav>
                    <ul>
                        {% if 'username' in session %}
                        <li>Welcome, {{ session['username'] }}</li>
                        <li><a href="{{ url_for('profile') }}">Profile</a></li>
                        <li><a href="{{ url_for('logout') }}">Logout</a></li>
                        {% else %}
                        <li><a href="{{ url_for('login') }}">Login</a></li>
                        <li><a href="{{ url_for('register') }}">Register</a></li>
                        {% endif %}
                    </ul>
                </nav>
            </div>
        </header>
        <section id="posts">
            <div class="container">
                <h2>Forum Posts</h2>
                {% for post in posts %}
                <div class="post">
                    <img src="{{ users[post.author]['avatar'] }}" alt="Avatar" class="avatar">
                    <strong>{{ post.author }}</strong> says:
                    <p>{{ post.content }}</p>
                </div>
                {% endfor %}
            </div>
        </section>
        <footer>
            <p>SecureForum &copy; 2023</p>
        </footer>
    </body>
    </html>
    ''', posts=posts, users=users)

# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username]['password'] == password:
            session['username'] = username
            return redirect(url_for('home'))
        else:
            return 'Invalid credentials', 401
    return render_template_string('''
    <!doctype html>
    <html>
    <head><title>SecureForum - Login</title></head>
    <body>
        <h1>Login</h1>
        <form method="post">
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <input type="submit" value="Login">
        </form>
    </body>
    </html>
    ''')

# Logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

# Register page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        if username in users:
            return 'User already exists', 400
        password = request.form['password']
        users[username] = {'password': password, 'avatar': '/static/avatars/default.png'}
        return redirect(url_for('login'))
    return render_template_string('''
    <!doctype html>
    <html>
    <head><title>SecureForum - Register</title></head>
    <body>
        <h1>Register</h1>
        <form method="post">
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <input type="submit" value="Register">
        </form>
    </body>
    </html>
    ''')

# User profile
@app.route('/profile')
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    user = users[username]
    return render_template_string('''
    <!doctype html>
    <html>
    <head><title>SecureForum - Profile</title></head>
    <body>
        <h1>{{ username }}'s Profile</h1>
        <img src="{{ user['avatar'] }}" alt="Avatar" style="width:100px;height:100px;"><br>
        <a href="{{ url_for('update_avatar') }}">Update Avatar</a><br>
        <a href="{{ url_for('home') }}">Back to Home</a>
    </body>
    </html>
    ''', username=username, user=user)

# Update profile picture
@app.route('/update_avatar', methods=['GET', 'POST'])
def update_avatar():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        avatar_url = request.form['avatar_url']
        # The application tries to prevent SSRF by validating the URL
        parsed_url = urlparse(avatar_url)
        if parsed_url.scheme not in ['http', 'https']:
            return 'Invalid URL scheme', 400
        if not re.match(r'^avatar\.trusted\.com$', parsed_url.netloc):
            return 'Invalid domain', 400
        # Fetch the avatar image
        try:
            # SSRF vulnerability: Inadequate hostname validation can be bypassed
            resp = requests.get(avatar_url, timeout=5)
            if resp.status_code == 200 and 'image' in resp.headers.get('Content-Type', ''):
                avatar_path = f"/static/avatars/{session['username']}.png"
                os.makedirs(os.path.dirname('.' + avatar_path), exist_ok=True)
                with open('.' + avatar_path, 'wb') as f:
                    f.write(resp.content)
                users[session['username']]['avatar'] = avatar_path
                return redirect(url_for('profile'))
            else:
                return 'Failed to fetch image', 400
        except Exception as e:
            return str(e), 500
    return render_template_string('''
    <!doctype html>
    <html>
    <head><title>SecureForum - Update Avatar</title></head>
    <body>
        <h1>Update Avatar</h1>
        <form method="post">
            Avatar URL: <input name="avatar_url"><br>
            <input type="submit" value="Update">
        </form>
    </body>
    </html>
    ''')

if __name__ == '__main__':
    app.run(debug=True)