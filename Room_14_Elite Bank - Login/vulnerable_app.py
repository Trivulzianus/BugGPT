from flask import Flask, request, render_template_string, redirect, url_for, session
from flask_session import Session

app = Flask(__name__)
app.secret_key = 'replace_with_a_random_key'  # In a real application, use a secure, random key
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# Dummy user database
users = {
    'user1': {'password': 'password1', 'name': 'John Doe', 'accounts': [1001]},
    'user2': {'password': 'password2', 'name': 'Jane Smith', 'accounts': [1002]},
    'user3': {'password': 'password3', 'name': 'Alice Johnson', 'accounts': [1003]},
}

# Dummy account database
accounts = {
    1001: {'balance': 5000, 'transactions': [
        {'date': '2023-10-01', 'amount': -100, 'description': 'ATM Withdrawal'},
        {'date': '2023-10-05', 'amount': 500, 'description': 'Salary Deposit'},
    ]},
    1002: {'balance': 10000, 'transactions': [
        {'date': '2023-10-02', 'amount': -200, 'description': 'Grocery Shopping'},
        {'date': '2023-10-06', 'amount': 1000, 'description': 'Freelance Payment'},
    ]},
    1003: {'balance': 7500, 'transactions': [
        {'date': '2023-10-03', 'amount': -150, 'description': 'Online Purchase'},
        {'date': '2023-10-07', 'amount': 700, 'description': 'Stock Dividends'},
    ]},
}

# Login page template
login_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Elite Bank - Login</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #e9ebee;}
        .login-container {width: 300px; margin: 0 auto; margin-top: 100px; padding: 20px; background-color: #fff; border-radius: 5px;}
        h1 {text-align: center; color: #333;}
        input[type=text], input[type=password] {width: 100%; padding: 10px; margin: 10px 0;}
        input[type=submit] {width: 100%; padding: 10px; background-color: #007bff; border: none; color: #fff; font-size: 16px; cursor: pointer;}
        input[type=submit]:hover {background-color: #0056b3;}
        .error {color: red; text-align: center;}
    </style>
</head>
<body>
    <div class="login-container">
        <h1>Elite Bank</h1>
        {% if error %}
        <p class="error">{{ error }}</p>
        {% endif %}
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required /><br/>
            <input type="password" name="password" placeholder="Password" required /><br/>
            <input type="submit" value="Login" />
        </form>
    </div>
</body>
</html>
'''

# Dashboard template
dashboard_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Elite Bank - Dashboard</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #f7f7f7;}
        .dashboard {width: 80%; margin: 0 auto; padding: 20px;}
        h1 {text-align: center;}
        .accounts {list-style-type: none; padding: 0;}
        .accounts li {background-color: #fff; margin: 10px 0; padding: 15px; border-radius: 5px;}
        .accounts a {text-decoration: none; color: #007bff; font-size: 18px;}
        .accounts a:hover {text-decoration: underline;}
    </style>
</head>
<body>
    <div class="dashboard">
        <h1>Welcome, {{ name }}</h1>
        <h2>Your Accounts</h2>
        <ul class="accounts">
        {% for account_id in accounts %}
            <li><a href="{{ url_for('account', account_id=account_id) }}">Account {{ account_id }}</a></li>
        {% endfor %}
        </ul>
    </div>
</body>
</html>
'''

# Account details template
account_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Elite Bank - Account {{ account_id }}</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #f7f7f7;}
        .account-details {width: 80%; margin: 0 auto; padding: 20px;}
        h1 {text-align: center;}
        .balance {font-size: 24px; margin-bottom: 20px;}
        table {width: 100%; border-collapse: collapse;}
        table, th, td {border: 1px solid #ccc;}
        th, td {padding: 12px; text-align: left;}
        th {background-color: #f0f0f0;}
    </style>
</head>
<body>
    <div class="account-details">
        <h1>Account {{ account_id }}</h1>
        <p class="balance">Balance: ${{ account.balance }}</p>
        <h2>Recent Transactions</h2>
        <table>
            <tr>
                <th>Date</th><th>Description</th><th>Amount</th>
            </tr>
            {% for txn in account.transactions %}
            <tr>
                <td>{{ txn.date }}</td><td>{{ txn.description }}</td><td>${{ txn.amount }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
</body>
</html>
'''

# Route for the login page
@app.route('/', methods=['GET', 'POST'])
def login():
    error = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Authenticate user
        if username in users and users[username]['password'] == password:
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid username or password'
    return render_template_string(login_template, error=error)

# Route for the dashboard
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    user = users[username]
    return render_template_string(dashboard_template, name=user['name'], accounts=user['accounts'])

# Route for account details (IDOR vulnerability here)
@app.route('/account/<int:account_id>')
def account(account_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    account = accounts.get(account_id)
    if not account:
        return "Account not found", 404
    # Vulnerability: Not verifying that the account belongs to the logged-in user
    return render_template_string(account_template, account_id=account_id, account=account)

if __name__ == '__main__':
    app.run(debug=True)