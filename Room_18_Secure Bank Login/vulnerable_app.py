from flask import Flask, render_template_string, request, redirect, url_for, session, abort
from flask_session import Session
import hashlib

app = Flask(__name__)

# Secret key for sessions
app.secret_key = 'supersecretkey'

# Configure server-side sessions
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# Function to generate account numbers (obfuscated for complexity)
def generate_account_number(username):
    return hashlib.sha256((username + 'secure_salt').encode()).hexdigest()

# Sample user database with obfuscated account numbers
users = {
    'alice': {
        'password': 'password123',
        'account_number': generate_account_number('alice'),
        'balance': 5000.0,
        'transactions': [
            {'date': '2023-01-01', 'amount': -100.0, 'description': 'ATM Withdrawal'},
            {'date': '2023-02-15', 'amount': 1500.0, 'description': 'Salary Deposit'},
        ]
    },
    'bob': {
        'password': 'mysecurepassword',
        'account_number': generate_account_number('bob'),
        'balance': 3000.0,
        'transactions': [
            {'date': '2023-01-10', 'amount': -50.0, 'description': 'Coffee Shop'},
            {'date': '2023-02-20', 'amount': -200.0, 'description': 'Online Shopping'},
        ]
    },
    'charlie': {
        'password': 'charliepwd',
        'account_number': generate_account_number('charlie'),
        'balance': 7500.0,
        'transactions': [
            {'date': '2023-03-05', 'amount': -500.0, 'description': 'Car Repair'},
            {'date': '2023-03-12', 'amount': 2000.0, 'description': 'Bonus Deposit'},
        ]
    },
}

# Login Page
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = users.get(username)
        if user and user['password'] == password:
            session['username'] = username
            return redirect(url_for('account'))
        else:
            error = 'Invalid credentials'
            return render_template_string(login_page, error=error)
    return render_template_string(login_page)

# Account Page
@app.route('/account')
def account():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    user = users.get(username)
    if not user:
        abort(404)

    # Get the 'id' parameter from the query string
    account_id = request.args.get('id')
    if account_id:
        # Here lies the complex IDOR vulnerability
        # The account_id is supposed to be a secure token, but the app uses predictable hashing
        for u_name, u_data in users.items():
            if u_data['account_number'] == account_id:
                user = u_data
                break

    return render_template_string(account_page, user=user)

# Templates as strings with professional design (using Bootstrap)
login_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secure Bank Login</title>
    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        body {
            background-image: url('https://www.publicdomainpictures.net/pictures/320000/velka/background-image.png');
            background-size: cover;
        }
        .login-container {
            margin-top: 100px;
            max-width: 400px;
            padding: 30px;
            background-color: rgba(255,255,255,0.9);
            border-radius: 10px;
        }
        .login-title {
            margin-bottom: 30px;
        }
    </style>
</head>
<body>
    <div class="container login-container">
        <h2 class="text-center login-title">Welcome to Secure Bank</h2>
        {% if error %}
        <div class="alert alert-danger">{{ error }}</div>
        {% endif %}
        <form method="post">
            <div class="form-group">
                <label for="username"><strong>Username</strong></label>
                <input type="text" class="form-control" id="username" name="username" placeholder="Enter your username" required autofocus>
            </div>
            <div class="form-group">
                <label for="password"><strong>Password</strong></label>
                <input type="password" class="form-control" id="password" name="password" placeholder="Enter your password" required>
            </div>
            <button type="submit" class="btn btn-primary btn-block">Login</button>
        </form>
        <p class="text-center mt-3"><small>Your security is our priority.</small></p>
    </div>
</body>
</html>
'''

account_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Account Overview - Secure Bank</title>
    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        .account-container {
            margin-top: 50px;
        }
        .balance-card {
            background-color: #f8f9fa;
            padding: 20px;
        }
        .transactions-table {
            margin-top: 30px;
        }
        .navbar {
            margin-bottom: 30px;
        }
        .logout-btn {
            color: #fff !important;
        }
    </style>
</head>
<body>
    <!-- Navbar -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
      <a class="navbar-brand" href="#">Secure Bank</a>
      <div class="collapse navbar-collapse">
        <ul class="navbar-nav ml-auto">
          <li class="nav-item">
            <a class="nav-link logout-btn" href="{{ url_for('login') }}">Logout</a>
          </li>
        </ul>
      </div>
    </nav>
    <div class="container account-container">
        <h2>Account Overview</h2>
        <div class="row">
            <div class="col-md-4">
                <div class="balance-card">
                    <h4>Account Number:</h4>
                    <p>{{ user['account_number'] }}</p>
                    <h4>Balance:</h4>
                    <p>$ {{ '%.2f' % user['balance'] }}</p>
                </div>
            </div>
        </div>
        <div class="transactions-table">
            <h3>Recent Transactions</h3>
            <table class="table table-striped">
                <thead>
                    <tr><th>Date</th><th>Description</th><th>Amount ($)</th></tr>
                </thead>
                <tbody>
                    {% for txn in user['transactions'] %}
                    <tr>
                        <td>{{ txn['date'] }}</td>
                        <td>{{ txn['description'] }}</td>
                        <td>{{ '%.2f' % txn['amount'] }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
'''

if __name__ == '__main__':
    app.run(debug=True)