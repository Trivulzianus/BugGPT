from flask import Flask, render_template_string, request, redirect, url_for, session
import xml.etree.ElementTree as ET
import os

app = Flask(__name__)
app.secret_key = 'SuperSecretKey'

# In-memory data storage
users = {}
posts = []

# Home page
@app.route('/')
def home():
    if 'username' in session:
        username = session['username']
        user = users.get(username, {})
        return render_template_string(home_page_html, username=username, posts=posts, user=user)
    else:
        return redirect(url_for('login'))

# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        session['username'] = username
        if username not in users:
            users[username] = {'bio': 'This user has not set a bio yet.'}
        return redirect(url_for('home'))
    return render_template_string(login_page_html)

# Logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

# Edit profile
@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    if request.method == 'POST':
        bio_xml = request.form['bio']
        try:
            # XXE vulnerability occurs here
            root = ET.fromstring(bio_xml)
            bio = root.text
            users[username]['bio'] = bio
        except ET.ParseError:
            users[username]['bio'] = 'Invalid XML provided.'
        return redirect(url_for('profile', username=username))
    return render_template_string(edit_profile_html, username=username)

# User profile
@app.route('/profile/<username>')
def profile(username):
    user = users.get(username)
    if user:
        return render_template_string(profile_page_html, username=username, bio=user['bio'])
    else:
        return 'User not found.', 404

# Create a new post
@app.route('/post', methods=['POST'])
def create_post():
    if 'username' in session:
        content = request.form['content']
        posts.insert(0, {'author': session['username'], 'content': content})
    return redirect(url_for('home'))

# HTML Templates
login_page_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SocialSphere - Login</title>
    <style>
        /* Add your CSS styles here for a professional look */
        body { font-family: Arial, sans-serif; background-color: #f0f2f5; }
        .container { max-width: 400px; margin: 100px auto; padding: 20px; background-color: white; border-radius: 8px; }
        h1 { text-align: center; }
        input { width: 100%; padding: 10px; margin: 10px 0; }
        button { width: 100%; padding: 10px; background-color: #1877f2; color: white; border: none; border-radius: 5px; }
        a { display: block; text-align: center; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>SocialSphere</h1>
        <form method="POST">
            <input type="text" name="username" placeholder="Enter your username" required>
            <button type="submit">Login</button>
        </form>
        <a href="#">Forgot Password?</a>
    </div>
</body>
</html>
'''

home_page_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SocialSphere - Home</title>
    <style>
        /* Add your CSS styles here for a professional look */
        body { font-family: Arial, sans-serif; background-color: #e9ebee; }
        .header { background-color: #4267b2; padding: 10px; color: white; }
        .header h1 { display: inline; }
        .header a { color: white; margin-left: 20px; }
        .content { max-width: 600px; margin: 20px auto; }
        .post-form textarea { width: 100%; padding: 10px; }
        .post-form button { float: right; padding: 10px 20px; background-color: #1877f2; color: white; border: none; border-radius: 5px; }
        .post { background-color: white; padding: 15px; margin: 15px 0; border-radius: 8px; }
        .post h2 { margin: 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>SocialSphere</h1>
        <a href="{{ url_for('profile', username=username) }}">Profile</a>
        <a href="{{ url_for('edit_profile') }}">Edit Profile</a>
        <a href="{{ url_for('logout') }}">Logout</a>
    </div>
    <div class="content">
        <div class="post-form">
            <form method="POST" action="{{ url_for('create_post') }}">
                <textarea name="content" rows="3" placeholder="What's on your mind?" required></textarea>
                <button type="submit">Post</button>
            </form>
            <div style="clear: both;"></div>
        </div>
        {% for post in posts %}
        <div class="post">
            <h2>{{ post.author }}</h2>
            <p>{{ post.content }}</p>
        </div>
        {% endfor %}
    </div>
</body>
</html>
'''

edit_profile_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SocialSphere - Edit Profile</title>
    <style>
        /* Add your CSS styles here for a professional look */
        body { font-family: Arial, sans-serif; background-color: #f0f2f5; }
        .container { max-width: 600px; margin: 50px auto; background-color: white; padding: 20px; border-radius: 8px; }
        h1 { text-align: center; }
        textarea { width: 100%; padding: 10px; }
        button { padding: 10px 20px; background-color: #42b72a; color: white; border: none; border-radius: 5px; }
        a { display: block; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Edit Profile</h1>
        <form method="POST">
            <label for="bio">Bio (XML Format):</label><br>
            <textarea name="bio" rows="5" required></textarea><br><br>
            <button type="submit">Save Changes</button>
        </form>
        <a href="{{ url_for('home') }}">Back to Home</a>
    </div>
</body>
</html>
'''

profile_page_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SocialSphere - {{ username }}'s Profile</title>
    <style>
        /* Add your CSS styles here for a professional look */
        body { font-family: Arial, sans-serif; background-color: #e9ebee; }
        .header { background-color: #4267b2; padding: 10px; color: white; }
        .header h1 { display: inline; }
        .header a { color: white; margin-left: 20px; }
        .content { max-width: 600px; margin: 20px auto; background-color: white; padding: 20px; border-radius: 8px; }
        h2 { margin-top: 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>SocialSphere</h1>
        <a href="{{ url_for('home') }}">Home</a>
        <a href="{{ url_for('logout') }}">Logout</a>
    </div>
    <div class="content">
        <h2>{{ username }}'s Profile</h2>
        <p><strong>Bio:</strong></p>
        <p>{{ bio }}</p>
    </div>
</body>
</html>
'''

if __name__ == '__main__':
    app.run(debug=True)