from flask import Flask, render_template, request, redirect, url_for, session, flash
from functools import wraps

# Initialize the Flask application
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure secret key in production

# Simulated database of users and accounts
users_db = {
    'john_doe': {'password': 'password123', 'account_id': 1001},
    'jane_smith': {'password': 'securepass', 'account_id': 1002},
    'alice_wong': {'password': 'alicepw', 'account_id': 1003},
}

accounts_db = {
    1001: {'name': 'John Doe', 'balance': 5000.75, 'transactions': [
        {'date': '2023-09-15', 'description': 'Grocery Store', 'amount': -150.25},
        {'date': '2023-09-12', 'description': 'Salary Deposit', 'amount': 2000.00},
    ]},
    1002: {'name': 'Jane Smith', 'balance': 8200.00, 'transactions': [
        {'date': '2023-09-18', 'description': 'Bookstore', 'amount': -45.50},
        {'date': '2023-09-14', 'description': 'Salary Deposit', 'amount': 3000.00},
    ]},
    1003: {'name': 'Alice Wong', 'balance': 1500.25, 'transactions': [
        {'date': '2023-09-20', 'description': 'Coffee Shop', 'amount': -5.75},
        {'date': '2023-09-10', 'description': 'Salary Deposit', 'amount': 1500.00},
    ]},
}

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('Please log in to access that page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Route for the homepage
@app.route('/')
def home():
    return render_template('home.html')

# Route for user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users_db.get(username)
        if user and user['password'] == password:
            session['logged_in'] = True
            session['username'] = username
            session['account_id'] = user['account_id']
            flash('Welcome, {}'.format(username), 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials. Please try again.', 'danger')
    return render_template('login.html')

# Route for user logout
@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

# User dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    account_id = session.get('account_id')
    account = accounts_db.get(account_id)
    return render_template('dashboard.html', account=account)

# Account details page with IDOR vulnerability
@app.route('/account/<int:account_id>')
@login_required
def account_details(account_id):
    # Vulnerable code: Does not check if the account_id belongs to the logged-in user
    account = accounts_db.get(account_id)
    if account:
        return render_template('account.html', account=account)
    else:
        flash('Account not found.', 'danger')
        return redirect(url_for('dashboard'))

# Run the Flask application
if __name__ == '__main__':
    app.run(debug=True)