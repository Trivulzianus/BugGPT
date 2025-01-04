from flask import Flask, render_template_string, request, redirect, session, url_for, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import base64

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///forum.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    password_hash = db.Column(db.String(128))
    posts = db.relationship('Post', backref='author', lazy='dynamic')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
        
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    author_id = db.Column(db.String(80))  # Storing username instead of user ID
    secret_info = db.Column(db.String(255))

def encode_id(post_id):
    key = 0xDEADBEEF
    obscured_id = post_id ^ key
    encoded = base64.urlsafe_b64encode(str(obscured_id).encode()).decode()
    return encoded

def decode_id(encoded_id):
    obscured_id = int(base64.urlsafe_b64decode(encoded_id.encode()).decode())
    key = 0xDEADBEEF
    post_id = obscured_id ^ key
    return post_id

@app.before_first_request
def create_tables():
    db.create_all()

INDEX_TEMPLATE = '''
<!doctype html>
<html>
<head>
    <title>CyberSec Forum</title>
</head>
<body>
<h1>Cyber Security Professionals Forum</h1>
<p>Welcome, {{ session['user_id'] }}!</p>
<a href="{{ url_for('create_post') }}">Create New Post</a>
<ul>
{% for post in posts %}
    <li><a href="{{ url_for('view_post', post_id=encode_id(post.id)) }}">{{ post.content[:30] }}...</a></li>
{% endfor %}
</ul>
<a href="{{ url_for('logout') }}">Logout</a>
</body>
</html>
'''

LOGIN_TEMPLATE = '''
<!doctype html>
<html>
<head>
    <title>Login - CyberSec Forum</title>
</head>
<body>
<h1>Login</h1>
{% if error %}
    <p style="color:red;">{{ error }}</p>
{% endif %}
<form method="post">
    Username: <input type="text" name="username"><br>
    Password: <input type="password" name="password"><br>
    <input type="submit" value="Login">
</form>
<p>Don't have an account? <a href="{{ url_for('register') }}">Register here</a></p>
</body>
</html>
'''

REGISTER_TEMPLATE = '''
<!doctype html>
<html>
<head>
    <title>Register - CyberSec Forum</title>
</head>
<body>
<h1>Register</h1>
{% if error %}
    <p style="color:red;">{{ error }}</p>
{% endif %}
<form method="post">
    Username: <input type="text" name="username"><br>
    Password: <input type="password" name="password"><br>
    <input type="submit" value="Register">
</form>
<p>Already have an account? <a href="{{ url_for('login') }}">Login here</a></p>
</body>
</html>
'''

CREATE_POST_TEMPLATE = '''
<!doctype html>
<html>
<head>
    <title>Create Post - CyberSec Forum</title>
</head>
<body>
<h1>Create Post</h1>
<form method="post">
    Content:<br>
    <textarea name="content" rows="10" cols="50"></textarea><br>
    <input type="submit" value="Post">
</form>
</body>
</html>
'''

POST_TEMPLATE = '''
<!doctype html>
<html>
<head>
    <title>View Post - CyberSec Forum</title>
</head>
<body>
<h1>View Post</h1>
<p>{{ post.content }}</p>
<p><em>Posted by {{ post.author_id }}</em></p>
{% if session['user_id'] == post.author_id %}
    <a href="{{ url_for('edit_post', post_id=encode_id(post.id)) }}">Edit Post</a>
{% endif %}
<a href="{{ url_for('index') }}">Back to Home</a>
</body>
</html>
'''

EDIT_POST_TEMPLATE = '''
<!doctype html>
<html>
<head>
    <title>Edit Post - CyberSec Forum</title>
</head>
<body>
<h1>Edit Post</h1>
<form method="post">
    Content:<br>
    <textarea name="content" rows="10" cols="50">{{ post.content }}</textarea><br>
    <input type="submit" value="Update">
</form>
<a href="{{ url_for('view_post', post_id=encode_id(post.id)) }}">Cancel</a>
</body>
</html>
'''

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    posts = Post.query.all()
    return render_template_string(INDEX_TEMPLATE, posts=posts, encode_id=encode_id)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id  # Correctly storing user ID
            return redirect(url_for('index'))
        else:
            error = 'Invalid username or password'
            return render_template_string(LOGIN_TEMPLATE, error=error)
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            error = 'Username already exists'
            return render_template_string(REGISTER_TEMPLATE, error=error)
        user = User(username=username, password_hash=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template_string(REGISTER_TEMPLATE)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/create_post', methods=['GET', 'POST'])
def create_post():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        content = request.form['content']
        user = User.query.get(session['user_id'])
        secret_info = f"Secret info of user {user.username}"
        post = Post(content=content, author_id=user.username, secret_info=secret_info)  # Incorrectly storing username instead of user ID
        db.session.add(post)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template_string(CREATE_POST_TEMPLATE)

@app.route('/post/<post_id>')
def view_post(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    try:
        real_post_id = decode_id(post_id)
    except Exception:
        abort(404)
    post = Post.query.get_or_404(real_post_id)
    return render_template_string(POST_TEMPLATE, post=post, encode_id=encode_id)

@app.route('/edit_post/<post_id>', methods=['GET', 'POST'])
def edit_post(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    try:
        real_post_id = decode_id(post_id)
    except Exception:
        abort(404)
    post = Post.query.get_or_404(real_post_id)
    # Authorization check is flawed due to mismatched data types
    if post.author_id != session['user_id']:
        abort(403)
    if request.method == 'POST':
        post.content = request.form['content']
        db.session.commit()
        return redirect(url_for('view_post', post_id=post_id))
    return render_template_string(EDIT_POST_TEMPLATE, post=post, encode_id=encode_id)

if __name__ == '__main__':
    app.run(debug=True)