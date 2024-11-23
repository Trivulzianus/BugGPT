from flask import Flask, request, render_template_string, redirect, url_for, make_response
from lxml import etree
import datetime
import random
import string

app = Flask(__name__)

# Simulated user database
users = {
    'admin': {
        'password': 'admin123',
        'accounts': [
            {
                'account_number': '123456789',
                'balance': 1000000
            }
        ]
    }
}

# Simulated session storage
sessions = {}

def generate_session_id():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=32))

@app.route('/', methods=['GET'])
def home():
    session_id = request.cookies.get('session_id')
    user = sessions.get(session_id)
    if user:
        return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template_string("""
<html>
<head>
<title>Secure Bank Login</title>
<style>
body { font-family: Arial, sans-serif; background-color: #e9ecef; }
.container { max-width: 400px; margin: auto; padding: 50px; background-color: white; margin-top: 100px; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
h2 { text-align: center; margin-bottom: 30px; }
input[type=text], input[type=password] { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ccc; border-radius: 4px; }
input[type=submit] { background-color: #007bff; color: white; padding: 12px; width: 100%; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
input[type=submit]:hover { background-color: #0056b3; }
</style>
</head>
<body>
<div class="container">
<h2>Member Login</h2>
<form method="POST" action="/login">
<label for="username">Username:</label>
<input type="text" name="username" required><br>
<label for="password">Password:</label>
<input type="password" name="password" required><br>
<input type="submit" value="Login">
</form>
</div>
</body>
</html>
        """)
    elif request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = users.get(username)
        if user and user['password'] == password:
            session_id = generate_session_id()
            sessions[session_id] = user
            response = make_response(redirect(url_for('dashboard')))
            response.set_cookie('session_id', session_id)
            return response
        else:
            return render_template_string("""
<html>
<head><title>Login Failed</title></head>
<body>
<h2>Login Failed</h2>
<p>Invalid username or password.</p>
<a href="/login">Try Again</a>
</body>
</html>
            """)

@app.route('/dashboard', methods=['GET'])
def dashboard():
    session_id = request.cookies.get('session_id')
    user = sessions.get(session_id)
    if user:
        return render_template_string("""
<html>
<head>
<title>Secure Bank Dashboard</title>
<style>
body { font-family: Arial, sans-serif; background-color: #f8f9fa; }
.container { max-width: 800px; margin: auto; padding: 20px; background-color: white; margin-top: 30px; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
h2 { text-align: center; margin-bottom: 20px; }
table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
th, td { padding: 12px; text-align: left; border-bottom: 1px solid #dee2e6; }
th { background-color: #343a40; color: white; }
.upload-form { background-color: #e9ecef; padding: 20px; border-radius: 5px; }
input[type=file] { padding: 5px; }
input[type=submit] { background-color: #28a745; color: white; padding: 10px; border: none; border-radius: 4px; cursor: pointer; }
input[type=submit]:hover { background-color: #218838; }
</style>
</head>
<body>
<div class="container">
<h2>Welcome, {{username}}</h2>
<h3>Your Accounts:</h3>
<table>
<tr><th>Account Number</th><th>Balance</th></tr>
{% for account in accounts %}
<tr><td>{{ account.account_number }}</td><td>${{ account.balance }}</td></tr>
{% endfor %}
</table>
<div class="upload-form">
<h3>Upload Account Data (XML):</h3>
<form method="POST" action="/upload" enctype="multipart/form-data">
<label for="xmlfile">Select XML file:</label><br>
<input type="file" name="xmlfile" required><br><br>
<input type="submit" value="Upload">
</form>
</div>
</div>
</body>
</html>
        """, username='admin', accounts=user['accounts'])
    else:
        return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
def upload():
    session_id = request.cookies.get('session_id')
    user = sessions.get(session_id)
    if not user:
        return redirect(url_for('login'))

    xmlfile = request.files.get('xmlfile')
    if not xmlfile:
        return 'No file uploaded.', 400

    xml_data = xmlfile.read()

    # Create a parser that allows external entities (This introduces the XXE vulnerability)
    parser = etree.XMLParser(load_dtd=True, no_network=False, resolve_entities=True)
    try:
        tree = etree.fromstring(xml_data, parser)
        # Process the XML data
        account_number = tree.find('account').text
        balance = tree.find('balance').text

        user['accounts'].append({
            'account_number': account_number,
            'balance': balance
        })

        return render_template_string("""
<html>
<head><title>Upload Successful</title></head>
<body>
<h2>Upload Successful</h2>
<p>Account data has been updated.</p>
<a href="/dashboard">Back to Dashboard</a>
</body>
</html>
        """)
    except Exception as e:
        return 'Error processing XML data: {}'.format(e), 500

if __name__ == '__main__':
    app.run(debug=True)