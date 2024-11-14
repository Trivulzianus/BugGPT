from flask import Flask, render_template, request, redirect, url_for, session
import os
from lxml import etree

# Initialize the Flask application
app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Needed for session management

# Simulate user data (in a real app, we'd use a database)
users = {'john_doe': 'password123'}
accounts = {
    'john_doe': {'balance': 5000, 'transactions': []}
}

# Create templates directory if it doesn't exist
if not os.path.exists('templates'):
    os.makedirs('templates')

# Write the HTML templates
# home.html
home_html = '''
<!DOCTYPE html>
<html>
<head>
    <title>SecureBank - Home</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f2f2f2; text-align: center; }
        h1 { color: #333; }
        a { text-decoration: none; color: #007BFF; font-size: 18px; }
    </style>
</head>
<body>
    <h1>Welcome to SecureBank</h1>
    <p>Your security is our priority.</p>
    <a href="{{ url_for('login') }}">Login to your account</a>
</body>
</html>
'''
with open('templates/home.html', 'w') as f:
    f.write(home_html)

# login.html
login_html = '''
<!DOCTYPE html>
<html>
<head>
    <title>SecureBank - Login</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f2f2f2; }
        .login-container { width: 300px; margin: auto; padding-top: 100px; }
        h1 { text-align: center; color: #333; }
        form { display: flex; flex-direction: column; }
        input { margin: 5px 0; padding: 8px; }
        .error { color: red; text-align: center; }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>Login to SecureBank</h1>
        {% if error %}
            <p class="error">{{ error }}</p>
        {% endif %}
        <form method="post">
            <input type="text" name="username" placeholder="Username" required/>
            <input type="password" name="password" placeholder="Password" required/>
            <input type="submit" value="Login"/>
        </form>
    </div>
</body>
</html>
'''
with open('templates/login.html', 'w') as f:
    f.write(login_html)

# dashboard.html
dashboard_html = '''
<!DOCTYPE html>
<html>
<head>
    <title>SecureBank - Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f2f2f2; }
        .dashboard-container { width: 800px; margin: auto; padding-top: 50px; }
        h1 { text-align: center; color: #333; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px; border: 1px solid #ccc; text-align: left; }
        th { background-color: #007BFF; color: white; }
        a { text-decoration: none; color: #007BFF; }
    </style>
</head>
<body>
    <div class="dashboard-container">
        <h1>Account Dashboard</h1>
        <p><strong>Balance:</strong> ${{ balance }}</p>
        <h2>Transactions</h2>
        {% if transactions %}
            <table>
                <tr>
                    <th>Date</th>
                    <th>Amount</th>
                    <th>Description</th>
                </tr>
                {% for txn in transactions %}
                <tr>
                    <td>{{ txn.date }}</td>
                    <td>${{ "%.2f"|format(txn.amount) }}</td>
                    <td>{{ txn.description }}</td>
                </tr>
                {% endfor %}
            </table>
        {% else %}
            <p>No transactions to display.</p>
        {% endif %}
        <p><a href="{{ url_for('import_transactions') }}">Import Transactions</a></p>
    </div>
</body>
</html>
'''
with open('templates/dashboard.html', 'w') as f:
    f.write(dashboard_html)

# import.html
import_html = '''
<!DOCTYPE html>
<html>
<head>
    <title>SecureBank - Import Transactions</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f2f2f2; }
        .import-container { width: 400px; margin: auto; padding-top: 100px; }
        h1 { text-align: center; color: #333; }
        form { display: flex; flex-direction: column; align-items: center; }
        input[type="file"] { margin: 20px 0; }
        input[type="submit"] { padding: 10px 20px; }
    </style>
</head>
<body>
    <div class="import-container">
        <h1>Import Transactions</h1>
        <form method="post" enctype="multipart/form-data">
            <input type="file" name="file" accept=".xml" required/>
            <input type="submit" value="Import"/>
        </form>
        <p><a href="{{ url_for('dashboard') }}">Back to Dashboard</a></p>
    </div>
</body>
</html>
'''
with open('templates/import.html', 'w') as f:
    f.write(import_html)

# Route for the home page
@app.route('/')
def home():
    return render_template('home.html')

# Route for user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username] == password:
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid Credentials. Please try again.'
    return render_template('login.html', error=error)

# Route for the user dashboard
@app.route('/dashboard')
def dashboard():
    username = session.get('username')
    if not username:
        return redirect(url_for('login'))
    user_account = accounts.get(username)
    balance = user_account.get('balance')
    transactions = user_account.get('transactions')
    return render_template('dashboard.html', balance=balance, transactions=transactions)

# Route for importing transactions
@app.route('/import', methods=['GET', 'POST'])
def import_transactions():
    username = session.get('username')
    if not username:
        return redirect(url_for('login'))
    if request.method == 'POST':
        # Handle file upload
        xml_file = request.files['file']
        if xml_file:
            # Read the XML file
            xml_content = xml_file.read()
            # Parse the XML content
            transactions = parse_xml_transactions(xml_content)
            # Add transactions to user's account
            accounts[username]['transactions'].extend(transactions)
            return redirect(url_for('dashboard'))
    return render_template('import.html')

# Function to parse XML transactions (contains XXE vulnerability)
def parse_xml_transactions(xml_content):
    # Vulnerable XML parser configuration
    parser = etree.XMLParser(load_dtd=True, no_network=False, resolve_entities=True)
    tree = etree.fromstring(xml_content, parser)
    transactions = []
    for txn in tree.findall('transaction'):
        date = txn.find('date').text
        amount = float(txn.find('amount').text)
        description = txn.find('description').text
        transactions.append({'date': date, 'amount': amount, 'description': description})
    return transactions

# Run the Flask application
if __name__ == '__main__':
    app.run(debug=True)