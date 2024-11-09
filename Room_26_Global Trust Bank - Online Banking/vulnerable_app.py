from flask import Flask, render_template_string, request, redirect, url_for, send_file, abort
from werkzeug.utils import secure_filename
from urllib.parse import urlparse, urljoin
import requests
import threading
import os

app = Flask(__name__)

# Secret API endpoint (SSRF vulnerability hidden here)
def get_exchange_rate(source_currency, target_currency):
    api_url = f"http://api.exchangerates.example/internal?source={source_currency}&target={target_currency}"
    response = requests.get(api_url)
    # In a real application, proper error checking and JSON parsing would be required
    return float(response.text)

@app.route('/')
def home():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Global Trust Bank - Online Banking</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #e9ecef; }
            .container { width: 400px; margin: 0 auto; padding-top: 100px; }
            h2 { text-align: center; color: #343a40; }
            form { background-color: #fff; padding: 20px; border-radius: 5px; }
            input[type=text], input[type=password] {
                width: 100%; padding: 10px; margin-bottom: 15px; border: 1px solid #ced4da; border-radius: 3px;
            }
            input[type=submit] {
                background-color: #007bff; color: white; padding: 10px; border: none; border-radius: 3px; width: 100%;
            }
            .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #6c757d; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>Global Trust Bank</h2>
            <form method="post" action="/login">
                <input type="text" id="username" name="username" placeholder="Username" required>
                <input type="password" id="password" name="password" placeholder="Password" required>
                <input type="submit" value="Login">
            </form>
        </div>
        <div class="footer">
            &copy; 2023 Global Trust Bank. All rights reserved.
        </div>
    </body>
    </html>
    ''')

@app.route('/login', methods=['POST'])
def login():
    # Simulate authentication (insecure - for demonstration purposes)
    username = request.form.get('username')
    password = request.form.get('password')
    # In a real application, authenticate the user
    return redirect(url_for('dashboard', user=username))

@app.route('/dashboard')
def dashboard():
    user = request.args.get('user', 'user')
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Global Trust Bank - Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #e9ecef; }
            .container { width: 800px; margin: 0 auto; padding-top: 50px; }
            h2 { text-align: center; color: #343a40; }
            .account-info { background-color: #fff; padding: 20px; border-radius: 5px; }
            .balance { font-size: 24px; color: #28a745; }
            .transaction { margin-top: 30px; }
            label { display: block; margin-bottom: 5px; color: #495057; }
            input[type=text], select {
                width: 100%; padding: 10px; margin-bottom: 15px; border: 1px solid #ced4da; border-radius: 3px;
            }
            input[type=submit] {
                background-color: #007bff; color: white; padding: 10px; border: none; border-radius: 3px;
            }
            .logout { text-align: right; }
            a { color: #007bff; text-decoration: none; }
            a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="logout">
                <a href="/">Logout</a>
            </div>
            <h2>Welcome, {{ user }}</h2>
            <div class="account-info">
                <p>Your current balance is <span class="balance">$10,000.00</span></p>
                <div class="transaction">
                    <h3>International Funds Transfer</h3>
                    <form method="post" action="/transfer">
                        <label for="account">Recipient Account Number:</label>
                        <input type="text" id="account" name="account" required>
                        <label for="amount">Amount (USD):</label>
                        <input type="text" id="amount" name="amount" required>
                        <label for="currency">Target Currency:</label>
                        <select id="currency" name="currency" required>
                            <option value="EUR">Euro (EUR)</option>
                            <option value="GBP">British Pound (GBP)</option>
                            <option value="JPY">Japanese Yen (JPY)</option>
                            <!-- More currencies could be added -->
                        </select>
                        <input type="submit" value="Transfer">
                    </form>
                </div>
            </div>
        </div>
    </body>
    </html>
    ''', user=user)

@app.route('/transfer', methods=['POST'])
def transfer():
    account = request.form.get('account')
    amount = request.form.get('amount')
    currency = request.form.get('currency')

    # In a real app, validate and process the transfer

    # Convert amount to target currency using internal API
    source_currency = 'USD'
    try:
        exchange_rate = get_exchange_rate(source_currency, currency)
        converted_amount = float(amount) * exchange_rate
    except:
        converted_amount = "Error retrieving exchange rate."

    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Transfer Confirmation</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #e9ecef; text-align: center; padding-top: 100px; }
            .message { background-color: #fff; display: inline-block; padding: 30px; border-radius: 5px; }
            h2 { color: #28a745; }
            p { color: #343a40; }
            a { color: #007bff; text-decoration: none; }
            a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <div class="message">
            <h2>Transfer Successful</h2>
            <p>You have successfully transferred ${{amount}} USD ({{converted_amount}} {{currency}}) to account {{account}}.</p>
            <a href="{{url_for('dashboard')}}">Return to Dashboard</a>
        </div>
    </body>
    </html>
    ''', amount=amount, converted_amount=converted_amount, currency=currency, account=account)

# Image upload functionality (complexity added)
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if request.method == 'POST':
        # Handle file upload
        file = request.files.get('avatar')
        if file:
            filename = secure_filename(file.filename)
            file_path = os.path.join('static', 'uploads', filename)
            file.save(file_path)
            avatar_url = url_for('static', filename=f'uploads/{filename}')
            # Save avatar URL in user profile (omitted)
            return render_template_string('''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Profile Updated</title>
            </head>
            <body>
                <h2>Profile Updated</h2>
                <p>Your avatar has been updated.</p>
                <img src="{{avatar_url}}" alt="Avatar" width="150">
                <br>
                <a href="{{url_for('dashboard')}}">Return to Dashboard</a>
            </body>
            </html>
            ''', avatar_url=avatar_url)
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Update Profile</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #e9ecef; }
            .container { width: 500px; margin: 0 auto; padding-top: 100px; }
            h2 { text-align: center; color: #343a40; }
            form { background-color: #fff; padding: 20px; border-radius: 5px; }
            input[type=file] {
                width: 100%; margin-bottom: 15px;
            }
            input[type=submit] {
                background-color: #007bff; color: white; padding: 10px; border: none; border-radius: 3px; width: 100%;
            }
            .back { text-align: center; margin-top: 15px; }
            a { color: #007bff; text-decoration: none; }
            a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>Update Your Profile</h2>
            <form method="post" enctype="multipart/form-data">
                <label for="avatar">Upload Avatar:</label>
                <input type="file" id="avatar" name="avatar" accept="image/*" required>
                <input type="submit" value="Update Profile">
            </form>
            <div class="back">
                <a href="{{url_for('dashboard')}}">Back to Dashboard</a>
            </div>
        </div>
    </body>
    </html>
    ''')

# Protect internal endpoints
@app.before_request
def block_internal_requests():
    # Prevent access to internal APIs from external requests
    if request.endpoint == 'get_exchange_rate':
        abort(404)

if __name__ == '__main__':
    # Ensure the 'uplo)