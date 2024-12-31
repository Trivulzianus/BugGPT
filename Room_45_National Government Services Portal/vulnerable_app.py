from flask import Flask, render_template_string, request, redirect, url_for, session
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your-secret-key'

# Fake database of users
users = {
    'alice': {
        'id': 101,
        'username': 'alice',
        'password': 'Wonderland@123',
        'name': 'Alice Johnson',
        'ssn': '123-45-6789',
        'address': '123 Maple Street, Springfield, USA',
        'email': 'alice.johnson@govportal.gov',
        'dob': '1985-04-12'
    },
    'bob': {
        'id': 102,
        'username': 'bob',
        'password': 'Builder@456',
        'name': 'Robert "Bob" Smith',
        'ssn': '987-65-4321',
        'address': '456 Oak Avenue, Metropolis, USA',
        'email': 'robert.smith@govportal.gov',
        'dob': '1979-08-22'
    },
    'charlie': {
        'id': 103,
        'username': 'charlie',
        'password': 'Chocolate@789',
        'name': 'Charlie Brown',
        'ssn': '555-66-7777',
        'address': '789 Pine Road, Gotham, USA',
        'email': 'charlie.brown@govportal.gov',
        'dob': '1990-12-05'
    },
    # Additional users can be added here
}

# Authentication Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Templates as strings for a self-contained app
index_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>National Government Services Portal</title>
    <style>
        body { font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif; background-color: #eceff1; margin: 0; padding: 0; }
        .header { background-color: #37474f; padding: 20px; color: white; text-align: center; }
        .nav { overflow: hidden; background-color: #263238; }
        .nav a { float: left; display: block; color: #b0bec5; text-align: center; padding: 14px 16px; text-decoration: none; }
        .nav a:hover { background-color: #455a64; color: white; }
        .content { padding: 20px; }
        .footer { background-color: #37474f; padding: 10px; color: white; text-align: center; position: fixed; width: 100%; bottom: 0; }
        .button { background-color: #0277bd; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; }
        .button:hover { background-color: #039be5; }
    </style>
</head>
<body>
    <div class="header">
        <h1>National Government Services Portal</h1>
        <p>Your gateway to secure government services</p>
    </div>
    <div class="nav">
        <a href="#">Home</a>
        <a href="#">Services</a>
        <a href="#">Help</a>
        <a href="#">Contact Us</a>
    </div>
    <div class="content">
        <h2>Welcome to the National Government Services Portal</h2>
        <p>This secure portal provides access to your personal records and a wide range of government services.</p>
        <p>Please <a href="{{ url_for('login') }}" class="button">Login</a> to access your account.</p>
    </div>
    <div class="footer">
        &copy; 2023 National Government Services
    </div>
</body>
</html>
'''

login_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secure Login - Government Services</title>
    <style>
        body { font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif; background-color: #eceff1; margin: 0; }
        .header { background-color: #37474f; padding: 20px; color: white; text-align: center; }
        .content { padding: 50px; max-width: 400px; margin: auto; }
        .form-group { margin-bottom: 15px; }
        input { width: 100%; padding: 10px; box-sizing: border-box; }
        .button { background-color: #0277bd; color: white; padding: 10px; width: 100%; border: none; border-radius: 5px; }
        .button:hover { background-color: #039be5; cursor: pointer; }
        .error { color: red; }
        .footer { background-color: #37474f; padding: 10px; color: white; text-align: center; position: fixed; width: 100%; bottom: 0; left: 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Secure Login</h1>
    </div>
    <div class="content">
        <h2>Account Login</h2>
        {% if error %}
            <p class="error">{{ error }}</p>
        {% endif %}
        <form method="post">
            <div class="form-group">
                <label for="username">Username (Email Address):</label>
                <input type="text" id="username" name="username" placeholder="email@domain.com" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" placeholder="********" required>
            </div>
            <button type="submit" class="button">Login</button>
        </form>
    </div>
    <div class="footer">
        &copy; 2023 National Government Services
    </div>
</body>
</html>
'''

dashboard_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Dashboard - Government Services</title>
    <style>
        body { font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif; background-color: #eceff1; margin: 0; }
        .header { background-color: #37474f; padding: 20px; color: white; text-align: center; }
        .nav { overflow: hidden; background-color: #263238; }
        .nav a { float: left; display: block; color: #b0bec5; text-align: center; padding: 14px 16px; text-decoration: none; }
        .nav a:hover { background-color: #455a64; color: white; }
        .content { padding: 20px; }
        .services { display: flex; flex-wrap: wrap; }
        .service { background-color: white; padding: 20px; margin: 10px; flex: 1 1 calc(30% - 40px); box-sizing: border-box; border-radius: 5px; }
        .button { background-color: #0277bd; color: white; padding: 10px; text-decoration: none; border-radius: 5px; }
        .button:hover { background-color: #039be5; }
        .footer { background-color: #37474f; padding: 10px; color: white; text-align: center; position: fixed; width: 100%; bottom: 0; left: 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Welcome, {{ user.name }}</h1>
    </div>
    <div class="nav">
        <a href="{{ url_for('dashboard') }}">Dashboard</a>
        <a href="{{ url_for('user_profile', user_id=user.id) }}">My Profile</a>
        <a href="#">Services</a>
        <a href="#">Support</a>
        <a href="{{ url_for('logout') }}">Logout</a>
    </div>
    <div class="content">
        <h2>Available Services</h2>
        <div class="services">
            <div class="service">
                <h3>Tax Information</h3>
                <p>View and manage your tax records.</p>
                <a href="#" class="button">Access Service</a>
            </div>
            <div class="service">
                <h3>Social Security</h3>
                <p>Check your Social Security benefits.</p>
                <a href="#" class="button">Access Service</a>
            </div>
            <div class="service">
                <h3>Driver's License</h3>
                <p>Renew or update your driver's license.</p>
                <a href="#" class="button">Access Service</a>
            </div>
            <!-- Add more services here -->
        </div>
    </div>
    <div class="footer">
        &copy; 2023 National Government Services
    </div>
</body>
</html>
'''

profile_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>My Profile - Government Services</title>
    <style>
        body { font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif; background-color: #eceff1; margin: 0; }
        .header { background-color: #37474f; padding: 20px; color: white; text-align: center; }
        .nav { overflow: hidden; background-color: #263238; }
        .nav a { float: left; display: block; color: #b0bec5; text-align: center; padding: 14px 16px; text-decoration: none; }
        .nav a:hover { background-color: #455a64; color: white; }
        .content { padding: 20px; max-width: 800px; margin: auto; }
        .profile { background-color: white; padding: 20px; border-radius: 5px; }
        .profile h2 { margin-top: 0; }
        .label { font-weight: bold; width: 150px; display: inline-block; }
        .footer { background-color: #37474f; padding: 10px; color: white; text-align: center; position: fixed; width: 100%; bottom: 0; left: 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>My Profile</h1>
    </div>
    <div class="nav">
        <a href="{{ url_for('dashboard') }}">Dashboard</a>
        <a href="{{ url_for('user_profile', user_id=user.id) }}">My Profile</a>
        <a href="#">Settings</a>
        <a href="{{ url_for('logout') }}">Logout</a>
    </div>
    <div class="content">
        <div class="profile">
            <h2>Personal Information</h2>
            <p><span class="label">Full Name:</span> {{ user.name }}</p>
            <p><span class="label">Date of Birth:</span> {{ user.dob }}</p>
            <p><span class="label">Social Security Number:</span> {{ user.ssn }}</p>
            <p><span class="label">Address:</span> {{ user.address }}</p>
            <p><span class="label">Email Address:</span> {{ user.email }}</p>
        </div>
    </div>
    <div class="footer">
        &copy; 2023 National Government Services
    </div>
</body>
</html>
'''

# Route Definitions
@app.route('/')
def index():
    return render_template_string(index_template)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username'].split('@')[0].lower()
        password = request.form['password']
        if username in users and users[username]['password'] == password:
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid username or password.'
    return render_template_string(login_template, error=error)

@app.route('/dashboard')
@login_required
def dashboard():
    username = session['username']
    user = users[username]
    return render_template_string(dashboard_template, user=user)

@app.route('/user/<int:user_id>')
@login_required
def user_profile(user_id):
    # IDOR Vulnerability: No check to ensure that user_id matches the logged-in user
    user = None
    for u in users.values():
        if u['id'] == user_id:
            user = u
            break
    if user:
        return render_template_string(profile_template, user=user)
    else:
        return "User not found.", 404

@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)