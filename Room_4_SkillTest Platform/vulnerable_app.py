from flask import Flask, request, redirect, url_for, render_template_string, session
from functools import wraps

# Flask setup
app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Secret key for session management

# Mock database
users = {
    '1': {'username': 'alice', 'password': 'alice123', 'data': 'Alice’s secret data.'},
    '2': {'username': 'bob', 'password': 'bob123', 'data': 'Bob’s confidential information.'},
    '3': {'username': 'charlie', 'password': 'charlie123', 'data': 'Charlie’s private notes.'}
}

# Decorator for login required
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def home():
    return render_template_string(home_page)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        for user_id, user in users.items():
            if user['username'] == username and user['password'] == password:
                session['user_id'] = user_id
                return redirect(url_for('dashboard'))
        error = "Invalid credentials. Please try again."
        return render_template_string(login_page, error=error)
    return render_template_string(login_page)

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']
    user = users.get(user_id)
    return render_template_string(dashboard_page, username=user['username'])

@app.route('/view_data')
@login_required
def view_data():
    # IDOR Vulnerability: Accepting user_id as a query parameter without proper authorization
    target_id = request.args.get('user_id', session['user_id'])
    target_user = users.get(target_id)
    if target_user:
        return render_template_string(view_data_page, data=target_user['data'], user_id=target_id)
    else:
        return "User not found.", 404

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('home'))

# HTML Templates with colorful and narrative design
home_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SkillTest Platform</title>
    <style>
        body { background-color: #f0f8ff; font-family: Arial, sans-serif; text-align: center; }
        h1 { color: #333399; }
        a { color: #ff4500; text-decoration: none; font-weight: bold; }
        a:hover { text-decoration: underline; }
        .container { margin-top: 100px; }
        .button { 
            background-color: #4CAF50; 
            border: none; 
            color: white; 
            padding: 15px 32px; 
            text-align: center; 
            text-decoration: none; 
            display: inline-block; 
            font-size: 16px; 
            margin: 4px 2px; 
            cursor: pointer; 
            border-radius: 12px;
        }
        .button-login { background-color: #008CBA; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome to SkillTest Platform</h1>
        <p>Embark on a journey to test and enhance your web security skills.</p>
        <a href="{{ url_for('login') }}" class="button button-login">Start Your Adventure</a>
    </div>
</body>
</html>
'''

login_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login - SkillTest Platform</title>
    <style>
        body { background-color: #e6ffe6; font-family: Arial, sans-serif; }
        .login-container {
            width: 300px; 
            margin: 100px auto; 
            padding: 20px; 
            border: 2px solid #4CAF50; 
            border-radius: 10px; 
            background-color: #ffffff;
        }
        h2 { color: #4CAF50; text-align: center; }
        input[type=text], input[type=password] {
            width: 100%; 
            padding: 12px 20px; 
            margin: 8px 0; 
            display: inline-block; 
            border: 1px solid #ccc; 
            box-sizing: border-box;
            border-radius: 4px;
        }
        .button {
            background-color: #4CAF50; 
            color: white; 
            padding: 14px 20px; 
            margin: 8px 0; 
            border: none; 
            cursor: pointer; 
            width: 100%; 
            border-radius: 4px;
        }
        .error { color: red; text-align: center; }
    </style>
</head>
<body>
    <div class="login-container">
        <h2>Login to Your Account</h2>
        {% if error %}
            <p class="error">{{ error }}</p>
        {% endif %}
        <form method="post">
            <label for="username"><b>Username</b></label>
            <input type="text" placeholder="Enter Username" name="username" required>

            <label for="password"><b>Password</b></label>
            <input type="password" placeholder="Enter Password" name="password" required>

            <button type="submit" class="button">Login</button>
        </form>
    </div>
</body>
</html>
'''

dashboard_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Dashboard - SkillTest Platform</title>
    <style>
        body { background: linear-gradient(to right, #8360c3, #2ebf91); font-family: Arial, sans-serif; color: #ffffff; }
        .dashboard-container {
            width: 80%; 
            margin: 50px auto; 
            padding: 20px; 
            background-color: rgba(0, 0, 0, 0.5); 
            border-radius: 10px;
        }
        h2 { text-align: center; }
        .nav { text-align: center; margin-top: 20px; }
        .nav a { 
            background-color: #ff5722; 
            color: white; 
            padding: 10px 20px; 
            margin: 5px; 
            text-decoration: none; 
            border-radius: 5px; 
            transition: background-color 0.3s;
        }
        .nav a:hover { background-color: #e64a19; }
    </style>
</head>
<body>
    <div class="dashboard-container">
        <h2>Welcome, {{ username.capitalize() }}!</h2>
        <p>Your mission: Explore the platform and uncover hidden vulnerabilities.</p>
        <div class="nav">
            <a href="{{ url_for('view_data') }}">View Your Data</a>
            <a href="{{ url_for('logout') }}">Logout</a>
        </div>
    </div>
</body>
</html>
'''

view_data_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Your Data - SkillTest Platform</title>
    <style>
        body { background-color: #fff8dc; font-family: Arial, sans-serif; }
        .data-container {
            width: 60%; 
            margin: 50px auto; 
            padding: 20px; 
            border: 2px solid #deb887; 
            border-radius: 10px; 
            background-color: #fffaf0;
        }
        h2 { color: #8b4513; text-align: center; }
        pre { background-color: #f5f5f5; padding: 15px; border-radius: 5px; }
        .back { text-align: center; margin-top: 20px; }
        .back a { 
            background-color: #8b4513; 
            color: white; 
            padding: 10px 20px; 
            text-decoration: none; 
            border-radius: 5px; 
            transition: background-color 0.3s;
        }
        .back a:hover { background-color: #5a2d0c; }
    </style>
</head>
<body>
    <div class="data-container">
        <h2>Confidential Data for User ID: {{ user_id }}</h2>
        <pre>{{ data }}</pre>
        <div class="back">
            <a href="{{ url_for('dashboard') }}">Back to Dashboard</a>
        </div>
    </div>
</body>
</html>
'''

# Function to open the web browser after the server starts
def open_browser():
    webbrowser.open_new('http://127.0.0.1:5000/')

# Run the app in a separate thread
def run_app():
    threading.Timer(1, open_browser).start()
    app.run()

# Execute the app
if __name__ == '__main__':
    run_app()
```

###)