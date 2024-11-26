from flask import Flask, render_template_string, request, redirect, url_for, session, flash
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Simulated user database
users = {
    "alice": {
        "password": "password123",
        "account_number": "1001",
        "name": "Alice Smith",
        "balance": "$10,000",
        "transactions": [
            {"date": "2023-09-10", "description": "Deposit", "amount": "$5,000"},
            {"date": "2023-09-12", "description": "Withdrawal", "amount": "-$1,000"},
        ],
    },
    "bob": {
        "password": "qwerty",
        "account_number": "1002",
        "name": "Bob Johnson",
        "balance": "$5,000",
        "transactions": [
            {"date": "2023-09-11", "description": "Deposit", "amount": "$5,000"},
        ],
    },
    "charlie": {
        "password": "charlie2023",
        "account_number": "1003",
        "name": "Charlie Davis",
        "balance": "$7,500",
        "transactions": [
            {"date": "2023-09-13", "description": "Transfer", "amount": "-$2,500"},
            {"date": "2023-09-14", "description": "Deposit", "amount": "$5,000"},
        ],
    },
}

# Login page template
login_page = '''
<!doctype html>
<html>
<head>
    <title>Global Bank - Secure Online Banking</title>
    <style>
        body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; }}
        .container {{
            width: 400px;
            margin: 100px auto;
            padding: 20px;
            background-color: #fff;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }}
        h1 {{ text-align: center; color: #333; }}
        input[type=text], input[type=password] {{
            width: 100%;
            padding: 10px;
            margin: 10px 0;
            border: 1px solid #ccc;
            border-radius: 4px;
        }}
        input[type=submit] {{
            width: 100%;
            padding: 10px;
            background-color: #4CAF50;
            border: none;
            border-radius: 4px;
            color: #fff;
            font-size: 16px;
            cursor: pointer;
        }}
        input[type=submit]:hover {{
            background-color: #45a049;
        }}
        .error {{ color: red; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Global Bank</h1>
        {% with messages = get_flashed_messages() %}
        {% if messages %}
        <div class="error">
            {% for message in messages %}
                <p>{{ message }}</p>
            {% endfor %}
        </div>
        {% endif %}
        {% endwith %}
        <form action="/login" method="post">
            <label for="username">Username:</label><br/>
            <input type="text" name="username" id="username" required><br/>
            <label for="password">Password:</label><br/>
            <input type="password" name="password" id="password" required><br/>
            <input type="submit" value="Login">
        </form>
    </div>
</body>
</html>
'''

# Account summary page template
account_page = '''
<!doctype html>
<html>
<head>
    <title>Global Bank - Account Summary</title>
    <style>
        body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; }}
        .container {{
            width: 600px;
            margin: 50px auto;
            padding: 20px;
            background-color: #fff;
            border-radius: 5px;
        }}
        h1 {{ color: #333; }}
        .balance {{
            font-size: 24px;
            color: green;
        }}
        a {{
            color: #4CAF50;
            text-decoration: none;
        }}
        a:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome, {{ name }}</h1>
        <p><strong>Account Number:</strong> {{ account_number }}</p>
        <p class="balance"><strong>Current Balance:</strong> {{ balance }}</p>
        <p><a href="/transactions?account_number={{ account_number }}">View Transaction History</a></p>
        <p><a href="/">Logout</a></p>
    </div>
</body>
</html>
'''

# Transaction history page template
transactions_page = '''
<!doctype html>
<html>
<head>
    <title>Global Bank - Transaction History</title>
    <style>
        body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; }}
        .container {{
            width: 700px;
            margin: 50px auto;
            padding: 20px;
            background-color: #fff;
            border-radius: 5px;
        }}
        h1 {{ color: #333; }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #f2f2f2;
        }}
        a {{
            color: #4CAF50;
            text-decoration: none;
        }}
        a:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Transaction History for Account {{ account_number }}</h1>
        <table>
            <tr>
                <th>Date</th>
                <th>Description</th>
                <th>Amount</th>
            </tr>
            {% for txn in transactions %}
            <tr>
                <td>{{ txn.date }}</td>
                <td>{{ txn.description }}</td>
                <td>{{ txn.amount }}</td>
            </tr>
            {% endfor %}
        </table>
        <p><a href="/account?account_number={{ account_number }}">Back to Account Summary</a></p>
        <p><a href="/">Logout</a></p>
    </div>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(login_page)

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user = users.get(username)
    if user and user['password'] == password:
        session['username'] = username
        account_number = user['account_number']
        # Redirect to account page with account number in URL (vulnerable to IDOR)
        return redirect(url_for('account', account_number=account_number))
    else:
        flash('Invalid username or password')
        return redirect(url_for('index'))

@app.route('/account')
def account():
    if 'username' not in session:
        flash('Please log in to continue')
        return redirect(url_for('index'))
    account_number = request.args.get('account_number')
    # Insecure: Does not verify if the account number belongs to the logged-in user
    user = next((u for u in users.values() if u['account_number'] == account_number), None)
    if user:
        return render_template_string(account_page, name=user['name'], account_number=account_number, balance=user['balance'])
    else:
        return "Invalid account number.", 404

@app.route('/transactions')
def transactions():
    if 'username' not in session:
        flash('Please log in to continue')
        return redirect(url_for('index'))
    account_number = request.args.get('account_number')
    # Insecure: Does not verify if the account number belongs to the logged-in user
    user = next((u for u in users.values() if u['account_number'] == account_number), None)
    if user:
        return render_template_string(
            transactions_page,
            account_number=account_number,
            transactions=user['transactions']
        )
    else:
        return "Invalid account number.", 404

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)