from flask import Flask, render_template_string, request, redirect, url_for, session
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Mock database
users = {
    'john.doe': {'password': 'password123', 'account_balance': 15000, 'account_number': 'ACC123456'},
    'jane.smith': {'password': 'securepass', 'account_balance': 23000, 'account_number': 'ACC654321'},
    # More users can be added for complexity
}

transactions = {
    'ACC123456': [
        {'date': '2023-10-01', 'description': 'Salary Deposit', 'amount': 5000},
        {'date': '2023-09-25', 'description': 'Grocery Store', 'amount': -150},
    ],
    'ACC654321': [
        {'date': '2023-10-02', 'description': 'Stock Dividend', 'amount': 200},
        {'date': '2023-09-28', 'description': 'Online Shopping', 'amount': -300},
    ],
}

# HTML Templates
login_page = """
<!DOCTYPE html>
<html>
<head>
    <title>Global Trust Bank - Secure Login</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f0f4f7; }
        .login-container { width: 300px; margin: 0 auto; padding-top: 100px; }
        .login-form { background-color: #fff; padding: 20px; border-radius: 5px; }
        .login-form h2 { margin-bottom: 20px; }
        .login-form input { width: 100%; padding: 10px; margin: 5px 0; }
        .login-form button { width: 100%; padding: 10px; background-color: #0078D7; color: #fff; border: none; }
        .login-form button:hover { background-color: #005a9e; }
    </style>
</head>
<body>
    <div class="login-container">
        <form class="login-form" action="{{ url_for('login') }}" method="post">
            <h2>Member Login</h2>
            <input type="text" name="username" placeholder="Username" required autofocus>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
            {% if error %}
            <p style="color:red;">{{ error }}</p>
            {% endif %}
        </form>
    </div>
</body>
</html>
"""

dashboard_page = """
<!DOCTYPE html>
<html>
<head>
    <title>Global Trust Bank - Account Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f0f4f7; }
        .dashboard { width: 800px; margin: 0 auto; padding-top: 50px; }
        .balance { background-color: #fff; padding: 20px; border-radius: 5px; }
        .balance h2 { margin-top: 0; }
        .transactions { margin-top: 20px; }
        table { width: 100%; border-collapse: collapse; background-color: #fff; }
        th, td { padding: 10px; border-bottom: 1px solid #ddd; text-align: left; }
        tr:hover { background-color: #f1f1f1; }
        .logout { float: right; }
    </style>
</head>
<body>
    <div class="dashboard">
        <a href="{{ url_for('logout') }}" class="logout">Logout</a>
        <div class="balance">
            <h2>Welcome, {{ username }}</h2>
            <p>Account Number: {{ account_number }}</p>
            <h3>Current Balance: ${{ account_balance }}</h3>
        </div>
        <div class="transactions">
            <h3>Recent Transactions</h3>
            <table>
                <tr><th>Date</th><th>Description</th><th>Amount ($)</th></tr>
                {% for txn in user_transactions %}
                <tr>
                    <td>{{ txn.date }}</td>
                    <td>{{ txn.description }}</td>
                    <td>{{ txn.amount }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
    </div>
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username]['password'] == password:
            session['username'] = username
            return redirect(url_for('dashboard', user_id=users[username]['account_number']))
        else:
            error = 'Invalid credentials. Please try again.'
    return render_template_string(login_page, error=error)

@app.route('/dashboard', methods=['GET'])
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Intentional IDOR vulnerability
    account_number = request.args.get('user_id')
    for user, data in users.items():
        if data['account_number'] == account_number:
            username = user
            account_balance = data['account_balance']
            user_transactions = transactions.get(account_number, [])
            return render_template_string(dashboard_page,
                                          username=username,
                                          account_number=account_number,
                                          account_balance=account_balance,
                                          user_transactions=user_transactions)
    return "Account not found.", 404

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)