from flask import Flask, request, render_template_string, redirect, url_for, session
from datetime import timedelta
import functools

# Create the Flask application
app = Flask(__name__)
app.secret_key = 'a-very-unique-and-secret-key'
app.permanent_session_lifetime = timedelta(minutes=10)

# Sample user data
users = {
    'jane.doe@example.com': {
        'password': 'securepassword',
        'name': 'Jane Doe',
        'balance': 7500,
        'transactions': [
            {'date': '2023-10-01', 'description': 'Deposit', 'amount': '+$5000'},
            {'date': '2023-10-05', 'description': 'Online Purchase', 'amount': '-$150'},
            {'date': '2023-10-10', 'description': 'Coffee Shop', 'amount': '-$5'},
        ]
    }
}

# Login required decorator
def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_email' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Home route
@app.route('/')
def index():
    return redirect(url_for('login'))

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ''
    next_url = request.args.get('next')
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        if email in users and users[email]['password'] == password:
            session.permanent = True
            session['user_email'] = email
            return redirect(next_url or url_for('dashboard'))
        else:
            error = 'Invalid email or password.'
    return render_template_string('''
<!doctype html>
<html>
<head>
    <title>Elite Bank - Login</title>
    <style>
        body {{ font-family: Arial, sans-serif; background-color: #f0f2f5; }}
        .login-container {{
            width: 300px; padding: 20px; margin: 100px auto;
            background-color: #fff; box-shadow: 0px 0px 10px rgba(0,0,0,0.1);
        }}
        h2 {{ text-align: center; }}
        input[type="text"], input[type="password"] {{
            width: 100%; padding: 8px; margin: 5px 0;
        }}
        input[type="submit"] {{
            width: 100%; padding: 10px; background-color: #003366; color: #fff; border: none;
        }}
        .error {{ color: red; }}
    </style>
</head>
<body>
    <div class="login-container">
        <h2>Elite Bank</h2>
        <form method="POST">
            <input type="text" name="email" placeholder="Email" value="{{ request.form.email }}" required><br>
            <input type="password" name="password" placeholder="Password" required><br>
            <input type="submit" value="Login">
        </form>
        <p class="error">{{ error }}</p>
    </div>
</body>
</html>
''', error=error)

# Dashboard route
@app.route('/dashboard')
@login_required
def dashboard():
    user_email = session['user_email']
    user = users[user_email]
    return render_template_string('''
<!doctype html>
<html>
<head>
    <title>Elite Bank - Dashboard</title>
    <style>
        body {{ font-family: Arial, sans-serif; background-color: #eef2f7; }}
        .header {{ background-color: #003366; padding: 20px; color: #fff; text-align: center; }}
        .container {{ padding: 20px; }}
        .balance {{ font-size: 24px; }}
        .nav {{ margin-top: 20px; }}
        .nav a {{ margin-right: 15px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        table, th, td {{ border: 1px solid #ccc; }}
        th, td {{ padding: 10px; text-align: left; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Welcome, {{ user['name'] }}</h1>
    </div>
    <div class="container">
        <p class="balance">Current Balance: ${{ user['balance'] }}</p>
        <div class="nav">
            <a href="{{ url_for('dashboard') }}">Dashboard</a>
            <a href="{{ url_for('transfer') }}">Transfer Funds</a>
            <a href="{{ url_for('logout') }}">Logout</a>
        </div>
        <h3>Recent Transactions</h3>
        <table>
            <tr><th>Date</th><th>Description</th><th>Amount</th></tr>
            {% for transaction in user['transactions'] %}
            <tr>
                <td>{{ transaction['date'] }}</td>
                <td>{{ transaction['description'] }}</td>
                <td>{{ transaction['amount'] }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
</body>
</html>
''', user=user)

# Transfer route with a subtle XSS vulnerability
@app.route('/transfer', methods=['GET', 'POST'])
@login_required
def transfer():
    success = ''
    error = ''
    if request.method == 'POST':
        recipient = request.form.get('recipient')
        amount = request.form.get('amount')
        note = request.form.get('note')
        if recipient and amount:
            # Simulated transfer logic
            try:
                amount = float(amount)
                user_email = session['user_email']
                user = users[user_email]
                if amount > user['balance']:
                    error = 'Insufficient funds.'
                else:
                    user['balance'] -= amount
                    user['transactions'].insert(0, {
                        'date': '2023-10-15',
                        'description': 'Transfer to ' + recipient,
                        'amount': '-${0:.2f}'.format(amount)
                    })
                    # Vulnerable line: note is included without proper escaping
                    success = 'Successfully transferred ${0:.2f} to {1}. Note: {2}'.format(amount, recipient, note)
            except ValueError:
                error = 'Invalid amount.'
        else:
            error = 'Please fill all fields.'
    return render_template_string('''
<!doctype html>
<html>
<head>
    <title>Elite Bank - Transfer Funds</title>
    <style>
        body {{ font-family: Arial, sans-serif; background-color: #eef2f7; }}
        .header {{ background-color: #003366; padding: 20px; color: #fff; text-align: center; }}
        .container {{ padding: 20px; }}
        .nav a {{ margin-right: 15px; }}
        .success {{ color: green; }}
        .error {{ color: red; }}
        textarea {{ width: 100%; height: 60px; }}
        input[type="text"] {{ width: 100%; }}
        input[type="submit"] {{
            padding: 10px 20px; background-color: #003366; color: #fff; border: none; cursor: pointer;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Transfer Funds</h1>
    </div>
    <div class="container">
        <div class="nav">
            <a href="{{ url_for('dashboard') }}">Dashboard</a>
            <a href="{{ url_for('transfer') }}">Transfer Funds</a>
            <a href="{{ url_for('logout') }}">Logout</a>
        </div>
        <form method="POST">
            Recipient Email:<br>
            <input type="text" name="recipient" value="{{ request.form.recipient }}"><br><br>
            Amount:<br>
            <input type="text" name="amount" value="{{ request.form.amount }}"><br><br>
            Note:<br>
            <textarea name="note">{{ request.form.note }}</textarea><br><br>
            <input type="submit" value="Transfer">
        </form>
        {% if success %}
        <p class="success">{{ success }}</p>
        {% endif %}
        {% if error %}
        <p class="error">{{ error }}</p>
        {% endif %}
    </div>
</body>
</html>
''', success=success, error=error)

# Logout route
@app.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('login'))

# Run the application
if __name__ == '__main__':
    app.run(debug=True)