from flask import Flask, render_template_string, request, redirect, url_for, session
from functools import wraps

# Create Flask app
app = Flask(__name__)
app.secret_key = 'SuperSecretKey'  # Needed for session management

# Sample user data
users = {
    'alice': {'password': 'password123', 'name': 'Alice Smith', 'posts': ['Hello world!', 'Loving this social network!']},
    'bob': {'password': 'qwerty', 'name': 'Bob Jones', 'posts': ['Just had a great coffee.', 'Anyone up for a chat?']},
    'charlie': {'password': 'letmein', 'name': 'Charlie Brown', 'posts': ['Feeling good today.', 'This is a secret post.']}
}

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Index route
@app.route('/')
def index():
    return render_template_string('''
    <html>
    <head>
        <title>FriendConnect - Connect with friends</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f0f2f5; }
            .login { margin: 100px auto; width: 300px; padding: 20px; background: white; border-radius: 5px; }
            .login h2 { margin-bottom: 20px; }
            .login input { width: 100%; padding: 10px; margin: 5px 0; }
            .login button { width: 100%; padding: 10px; background: #1877f2; border: none; color: white; font-size: 16px; }
        </style>
    </head>
    <body>
        <div class="login">
            <h2>Login to FriendConnect</h2>
            <form action="{{ url_for('login') }}" method="post">
                <input type="text" name="username" placeholder="Username"/><br/>
                <input type="password" name="password" placeholder="Password"/><br/>
                <button type="submit">Login</button>
            </form>
        </div>
    </body>
    </html>
    ''')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Authenticate user
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username]['password'] == password:
            session['username'] = username
            next_url = request.args.get('next')
            return redirect(next_url or url_for('home'))
        else:
            return "Invalid credentials. <a href='/'>Try again.</a>"
    else:
        return redirect(url_for('index'))

# Home route
@app.route('/home')
@login_required
def home():
    username = session['username']
    name = users[username]['name']
    posts = users[username]['posts']
    return render_template_string('''
    <html>
    <head>
        <title>FriendConnect - Home</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f0f2f5; }
            .header { background: #fff; padding: 10px; }
            .header h1 { display: inline-block; }
            .header a { float: right; margin-top: 20px; text-decoration: none; }
            .content { width: 600px; margin: 20px auto; }
            .post { background: white; padding: 10px; margin-bottom: 10px; border-radius: 5px; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>FriendConnect</h1>
            <a href="{{ url_for('logout') }}">Logout</a>
        </div>
        <div class="content">
            <h2>Welcome, {{ name }}!</h2>
            <h3>Your Posts:</h3>
            {% for post in posts %}
            <div class="post">{{ post }}</div>
            {% endfor %}
            <h3>Browse Profiles:</h3>
            <ul>
                {% for user in users %}
                {% if user != username %}
                <li><a href="{{ url_for('profile', user_id=user) }}">{{ users[user]['name'] }}</a></li>
                {% endif %}
                {% endfor %}
            </ul>
        </div>
    </body>
    </html>
    ''', name=name, posts=posts, users=users, username=username)

# Profile route with IDOR vulnerability
@app.route('/profile')
@login_required
def profile():
    # Intentional IDOR vulnerability
    user_id = request.args.get('user_id')
    if user_id in users:
        name = users[user_id]['name']
        posts = users[user_id]['posts']
        return render_template_string('''
        <html>
        <head>
            <title>FriendConnect - {{ name }}'s Profile</title>
            <style>
                body { font-family: Arial, sans-serif; background-color: #f0f2f5; }
                .header { background: #fff; padding: 10px; }
                .header h1 { display: inline-block; }
                .header a { float: right; margin-top: 20px; text-decoration: none; }
                .content { width: 600px; margin: 20px auto; }
                .post { background: white; padding: 10px; margin-bottom: 10px; border-radius: 5px; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>FriendConnect</h1>
                <a href="{{ url_for('logout') }}">Logout</a>
            </div>
            <div class="content">
                <h2>{{ name }}'s Posts</h2>
                {% for post in posts %}
                <div class="post">{{ post }}</div>
                {% endfor %}
                <a href="{{ url_for('home') }}">Back to Home</a>
            </div>
        </body>
        </html>
        ''', name=name, posts=posts)
    else:
        return "User not found."

# Logout route
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

# Run the app
if __name__ == '__main__':
    app.run(debug=True)