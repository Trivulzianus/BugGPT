from flask import Flask, request, render_template_string, redirect, url_for

app = Flask(__name__)

# Sample user data
users = {
    '1': {
        'name': 'John Doe',
        'balance': '$10,000',
        'transactions': [
            {'date': '2023-10-01', 'description': 'Deposit', 'amount': '$5,000'},
            {'date': '2023-10-05', 'description': 'Withdrawal', 'amount': '$1,000'},
        ]
    },
    '2': {
        'name': 'Jane Smith',
        'balance': '$20,000',
        'transactions': [
            {'date': '2023-10-02', 'description': 'Deposit', 'amount': '$10,000'},
            {'date': '2023-10-06', 'description': 'Withdrawal', 'amount': '$2,000'},
        ]
    },
    '3': {
        'name': 'Alice Johnson',
        'balance': '$15,000',
        'transactions': [
            {'date': '2023-10-03', 'description': 'Deposit', 'amount': '$7,500'},
            {'date': '2023-10-07', 'description': 'Withdrawal', 'amount': '$1,500'},
        ]
    },
}

@app.route('/')
def index():
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secure Bank Online</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        body {
            background-image: url('https://www.publicdomainpictures.net/pictures/320000/velka/background-image.png');
            background-size: cover;
        }
        .container {
            margin-top: 100px;
            background: rgba(255,255,255,0.9);
            padding: 40px;
            border-radius: 10px;
        }
        .navbar {
            background-color: #003366;
        }
        .navbar-brand, .nav-link, .navbar-text {
            color: #fff !important;
        }
        footer {
            position: fixed;
            bottom: 0;
            width: 100%;
            background-color: #003366;
            color: #fff;
            text-align: center;
            padding: 10px 0;
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg">
      <a class="navbar-brand" href="#">Secure Bank Online</a>
      <div class="collapse navbar-collapse">
        <span class="navbar-text ml-auto">
          Banking Made Easy
        </span>
      </div>
    </nav>
    <div class="container text-center">
        <h1 class="mb-4">Welcome to Secure Bank Online</h1>
        <p class="lead">Access your account securely anytime, anywhere.</p>
        <form action="{{ url_for('account') }}" method="get" class="mt-5">
            <div class="form-group">
                <input type="text" class="form-control form-control-lg" id="user_id" name="id" placeholder="Enter Your User ID" required>
            </div>
            <button type="submit" class="btn btn-primary btn-lg">Access Account</button>
        </form>
    </div>
    <footer>
        &copy; 2023 Secure Bank Online. All rights reserved.
    </footer>
</body>
</html>
    ''')

@app.route('/account')
def account():
    user_id = request.args.get('id')
    user = users.get(user_id)
    if not user:
        return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Account Not Found - Secure Bank Online</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        body {
            background-color: #f8d7da;
        }
        .container {
            margin-top: 100px;
            text-align: center;
        }
        .alert {
            display: inline-block;
            text-align: left;
        }
        a {
            color: #721c24;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="alert alert-danger" role="alert">
            <h4 class="alert-heading">Account Not Found</h4>
            <p>The account you are trying to access does not exist.</p>
            <hr>
            <p class="mb-0"><a href="{{ url_for('index') }}">Return to Home</a></p>
        </div>
    </div>
</body>
</html>
        ''')
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Account Summary - Secure Bank Online</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        .navbar {
            background-color: #003366;
        }
        .navbar-brand, .nav-link, .navbar-text {
            color: #fff !important;
        }
        .container {
            margin-top: 50px;
        }
        footer {
            margin-top: 50px;
            background-color: #003366;
            color: #fff;
            text-align: center;
            padding: 10px 0;
        }
        .btn-logout {
            background-color: #003366;
            color: #fff;
        }
        .btn-logout:hover {
            background-color: #002244;
            color: #fff;
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg">
      <a class="navbar-brand" href="#">Secure Bank Online</a>
      <div class="collapse navbar-collapse">
        <span class="navbar-text ml-auto">
          Logged in as {{ user.name }}
        </span>
      </div>
    </nav>
    <div class="container">
        <h2 class="mb-4">Account Summary</h2>
        <div class="card">
          <div class="card-body">
            <h5 class="card-title">Account Holder: {{ user.name }}</h5>
            <p class="card-text"><strong>Current Balance:</strong> {{ user.balance }}</p>
          </div>
        </div>
        <h3 class="mt-5">Recent Transactions</h3>
        <table class="table table-hover mt-3">
            <thead class="thead-dark">
                <tr>
                    <th>Date</th>
                    <th>Description</th>
                    <th>Amount</th>
                </tr>
            </thead>
            <tbody>
                {% for transaction in user.transactions %}
                <tr>
                    <td>{{ transaction.date }}</td>
                    <td>{{ transaction.description }}</td>
                    <td>{{ transaction.amount }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        <a href="{{ url_for('index') }}" class="btn btn-logout mt-4">Log Out</a>
    </div>
    <footer>
        &copy; 2023 Secure Bank Online. All rights reserved.
    </footer>
</body>
</html>
    ''', user=user)

if __name__ == '__main__':
    app.run(debug=True)