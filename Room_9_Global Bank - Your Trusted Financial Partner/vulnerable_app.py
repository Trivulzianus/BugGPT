from flask import Flask, request, render_template_string, redirect, url_for
import requests

app = Flask(__name__)

# Simulated user database
users = {
    'alice': {'password': 'wonderland', 'balance': 2500},
    'bob': {'password': 'builder', 'balance': 1500},
}

@app.route('/')
def home():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Global Bank - Your Trusted Financial Partner</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f0f2f5; }
            .container { width: 50%; margin: auto; padding: 50px; background-color: white; }
            h1 { color: #2c3e50; }
            a { text-decoration: none; color: #2980b9; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Welcome to Global Bank</h1>
            <p>Your trusted partner in achieving financial success.</p>
            <p><a href="{{ url_for('login') }}">Secure Login</a></p>
        </div>
    </body>
    </html>
    ''')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = users.get(username)
        if user and user['password'] == password:
            return redirect(url_for('dashboard', username=username))
        else:
            error = 'Invalid username or password.'
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login - Global Bank</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f0f2f5; }
            .container { width: 30%; margin: auto; padding: 50px; background-color: white; margin-top: 100px; }
            h2 { color: #2c3e50; }
            .error { color: red; }
            input { width: 100%; padding: 10px; margin: 5px 0; }
            button { padding: 10px; background-color: #2980b9; color: white; border: none; width: 100%; }
            a { text-decoration: none; color: #2980b9; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>Account Login</h2>
            {% if error %}
                <p class="error">{{ error }}</p>
            {% endif %}
            <form method="post">
                <input type="text" name="username" placeholder="Username" required/>
                <input type="password" name="password" placeholder="Password" required/>
                <button type="submit">Login</button>
            </form>
            <p><a href="{{ url_for('home') }}">Back to Home</a></p>
        </div>
    </body>
    </html>
    ''', error=error)

@app.route('/dashboard/<username>')
def dashboard(username):
    user = users.get(username)
    if not user:
        return redirect(url_for('login'))
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Dashboard - Global Bank</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f0f2f5; }
            .container { width: 60%; margin: auto; padding: 50px; background-color: white; }
            h2 { color: #2c3e50; }
            .balance { font-size: 1.5em; color: #27ae60; }
            a { text-decoration: none; color: #2980b9; }
            .button { padding: 10px 20px; background-color: #2980b9; color: white; border: none; text-decoration: none; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>Hello, {{ username }}</h2>
            <p>Your current balance is:</p>
            <p class="balance">$ {{ user['balance'] }}</p>
            <p><a href="{{ url_for('import_data', username=username) }}" class="button">Import Account Data</a></p>
            <p><a href="{{ url_for('home') }}">Logout</a></p>
        </div>
    </body>
    </html>
    ''', username=username, user=user)

@app.route('/import/<username>', methods=['GET', 'POST'])
def import_data(username):
    user = users.get(username)
    if not user:
        return redirect(url_for('login'))
    message = None
    if request.method == 'POST':
        data_url = request.form.get('data_url')
        try:
            # Vulnerable to SSRF
            response = requests.get(data_url)
            # Simulate data processing
            imported_data = response.text
            message = 'Data imported successfully!'
        except Exception as e:
            message = 'Failed to import data.'
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Import Data - Global Bank</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f0f2f5; }
            .container { width: 40%; margin: auto; padding: 50px; background-color: white; margin-top: 50px; }
            h2 { color: #2c3e50; }
            .message { color: green; }
            input { width: 100%; padding: 10px; margin: 5px 0; }
            button { padding: 10px; background-color: #2980b9; color: white; border: none; width: 100%; }
            a { text-decoration: none; color: #2980b9; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>Import Account Data</h2>
            {% if message %}
                <p class="message">{{ message }}</p>
            {% endif %}
            <form method="post">
                <input type="text" name="data_url" placeholder="Enter data URL" required/>
                <button type="submit">Import Data</button>
            </form>
            <p><a href="{{ url_for('dashboard', username=username) }}">Back to Dashboard</a></p>
        </div>
    </body>
    </html>
    ''', username=username, message=message)

if __name__ == '__main__':
    app.run(debug=True)