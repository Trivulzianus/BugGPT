from flask import Flask, render_template_string, request, redirect, url_for, session, abort, send_file
from werkzeug.utils import secure_filename
from functools import wraps
import secrets

# Create Flask app
app = Flask(__name__)
app.secret_key = 'super-secret-key'  # In real life, use a secure, random key

# In-memory 'database'
USERS = {
    'alice': {'password': 'password123', 'files': []},
    'bob': {'password': '1234password', 'files': []}
}

FILES = {}  # File ID to file info mapping

# Decorator to require login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Home page
@app.route('/')
def index():
    return render_template_string('''
    <html>
    <head>
    <title>ShareSphere - Your Content Sharing Platform</title>
    <style>
    body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0; }
    .header { background-color: #50b3a2; color: #fff; padding: 20px; text-align: center; }
    .nav { padding: 10px; text-align: center; background-color: #eee; }
    .nav a { margin: 0 10px; color: #333; text-decoration: none; font-weight: bold; }
    .content { padding: 20px; }
    a.button { background-color: #50b3a2; color: #fff; padding: 10px 20px; text-decoration: none; }
    </style>
    </head>
    <body>
    <div class="header">
        <h1>Welcome to ShareSphere</h1>
    </div>
    <div class="nav">
    {% if session.username %}
        <span>Hello, {{ session.username }}!</span>
        <a href="{{ url_for('index') }}">Home</a>
        <a href="{{ url_for('upload') }}">Upload File</a>
        <a href="{{ url_for('my_files') }}">My Files</a>
        <a href="{{ url_for('logout') }}">Logout</a>
    {% else %}
        <a href="{{ url_for('index') }}">Home</a>
        <a href="{{ url_for('login') }}">Login</a>
    {% endif %}
    </div>
    <div class="content">
        <h2>Discover the simplicity of secure file sharing.</h2>
        <p>ShareSphere is a cutting-edge content sharing platform where you can securely upload and share your files.</p>
        {% if not session.username %}
        <p><a href="{{ url_for('login') }}" class="button">Get Started</a></p>
        {% endif %}
    </div>
    </body>
    </html>
    ''')

# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = USERS.get(username)
        if user and user['password'] == password:
            session['username'] = username
            return redirect(url_for('index'))
        else:
            return render_template_string('''
                <html>
                <head><title>Login - ShareSphere</title></head>
                <body>
                <h1>Login Failed</h1>
                <p>Invalid credentials.</p>
                <p><a href="{{ url_for('login') }}">Try again</a></p>
                </body>
                </html>
            ''')
    return render_template_string('''
    <html>
    <head>
    <title>Login - ShareSphere</title>
    <style>
    body { font-family: Arial, sans-serif; background-color: #f4f4f4; }
    .login-container { width: 300px; margin: 100px auto; background-color: #fff; padding: 20px; border-radius: 5px; }
    input[type=text], input[type=password] { width: 100%; padding: 10px; margin: 5px 0; }
    input[type=submit] { width: 100%; padding: 10px; background-color: #50b3a2; color: #fff; border: none; cursor: pointer; }
    </style>
    </head>
    <body>
    <div class="login-container">
    <h1>Login</h1>
    <form method="post">
        <label>Username:</label>
        <input type='text' name='username' required><br>
        <label>Password:</label>
        <input type='password' name='password' required><br>
        <input type='submit' value='Login'>
    </form>
    </div>
    </body>
    </html>
    ''')

# Logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

# Upload file
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            filename = secure_filename(file.filename)
            file_id = secrets.token_hex(8)
            if not os.path.exists('uploads'):
                os.makedirs('uploads')
            filepath = os.path.join('uploads', file_id + '_' + filename)
            file.save(filepath)
            
            # Save file info
            file_info = {
                'id': file_id,
                'owner': session['username'],
                'filename': filename,
                'filepath': filepath
            }
            FILES[file_id] = file_info
            USERS[session['username']]['files'].append(file_id)
            return redirect(url_for('my_files'))
    return render_template_string('''
    <html>
    <head>
    <title>Upload File - ShareSphere</title>
    <style>
    body { font-family: Arial, sans-serif; background-color: #f4f4f4; }
    .upload-container { width: 500px; margin: 50px auto; background-color: #fff; padding: 20px; border-radius: 5px; }
    input[type=file] { width: 100%; padding: 10px; }
    input[type=submit] { padding: 10px 20px; background-color: #50b3a2; color: #fff; border: none; cursor: pointer; }
    </style>
    </head>
    <body>
    <div class="upload-container">
    <h1>Upload File</h1>
    <form method="post" enctype="multipart/form-data">
        <input type='file' name='file' required><br><br>
        <input type='submit' value='Upload'>
    </form>
    </div>
    </body>
    </html>
    ''')

# List user's files
@app.route('/my_files')
@login_required
def my_files():
    user_files = [FILES[file_id] for file_id in USERS[session['username']]['files']]
    return render_template_string('''
    <html>
    <head>
    <title>My Files - ShareSphere</title>
    <style>
    body { font-family: Arial, sans-serif; background-color: #f4f4f4; }
    .files-container { width: 600px; margin: 50px auto; background-color: #fff; padding: 20px; border-radius: 5px; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
    a { color: #50b3a2; text-decoration: none; }
    </style>
    </head>
    <body>
    <div class="files-container">
    <h1>My Files</h1>
    {% if files %}
    <table>
        <tr>
            <th>Filename</th>
            <th>Action</th>
        </tr>
    {% for file in files %}
        <tr>
            <td>{{ file.filename }}</td>
            <td><a href="{{ url_for('download', file_id=file.id) }}">Download</a></td>
        </tr>
    {% endfor %}
    </table>
    {% else %}
        <p>You have not uploaded any files yet.</p>
    {% endif %}
    </div>
    </body>
    </html>
    ''', files=user_files)

# Download file (Vulnerable to IDOR)
@app.route('/download/<file_id>')
@login_required
def download(file_id):
    file_info = FILES.get(file_id)
    if file_info:
        # IDOR vulnerability: No check if the file belongs to the logged-in user
        return send_file(file_info['filepath'], as_attachment=True, attachment_filename=file_info['filename'])
    else:
        abort(404)

# Run the app
if __name__ == '__main__':
    app.run(debug=True)