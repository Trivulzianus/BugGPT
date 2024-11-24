from flask import Flask, request, render_template_string, redirect, url_for, session
import requests

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# HTML templates
homepage_html = '''
<!DOCTYPE html>
<html>
<head>
    <title>Secure National Bank</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f2f2f2; }
        .container { width: 400px; margin: 100px auto; background-color: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); }
        h1 { text-align: center; color: #333; margin-bottom: 30px; }
        input[type=text], input[type=password] { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ccc; border-radius: 4px; }
        input[type=submit] { width: 100%; background-color: #4CAF50; color: white; padding: 14px 20px; margin-top: 20px; border: none; border-radius: 4px; cursor: pointer; }
        input[type=submit]:hover { background-color: #45a049; }
        .footer { text-align: center; margin-top: 50px; color: #aaa; font-size: 12px; }
        .error { color: red; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Secure National Bank</h1>
        {% if error %}
            <p class="error">{{ error }}</p>
        {% endif %}
        <form action="/login" method="post">
            <input type="text" name="username" placeholder="Username" required /><br/>
            <input type="password" name="password" placeholder="Password" required /><br/>
            <input type="submit" value="Login" />
        </form>
    </div>
    <div class="footer">
        <p>&copy; 2023 Secure National Bank. All rights reserved.</p>
    </div>
</body>
</html>
'''

dashboard_html = '''
<!DOCTYPE html>
<html>
<head>
    <title>Secure National Bank - Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f2f2f2; }
        .container { width: 800px; margin: 50px auto; background-color: #fff; padding: 40px; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); }
        h1 { text-align: center; color: #333; }
        .balance { text-align: center; font-size: 24px; margin-top: 30px; }
        .actions { text-align: center; margin-top: 50px; }
        .actions a { margin: 0 15px; text-decoration: none; color: #4CAF50; font-weight: bold; }
        .actions a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome, {{ username }}</h1>
        <p class="balance">Current Balance: <strong>$10,000.00</strong></p>
        <div class="actions">
            <a href="/transfer">Transfer Funds</a>
            <a href="/preview-form">Preview External Content</a>
            <a href="/logout">Logout</a>
        </div>
    </div>
</body>
</html>
'''

preview_form_html = '''
<!DOCTYPE html>
<html>
<head>
    <title>Secure National Bank - Preview Content</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f2f2f2; }
        .container { width: 600px; margin: 50px auto; background-color: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); }
        h1 { text-align: center; color: #333; margin-bottom: 20px; }
        form { text-align: center; }
        input[type=text] { width: 80%; padding: 12px; margin: 8px 0; border: 1px solid #ccc; border-radius: 4px; }
        input[type=submit] { width: 50%; background-color: #4CAF50; color: white; padding: 12px; margin-top: 20px; border: none; border-radius: 4px; cursor: pointer; }
        input[type=submit]:hover { background-color: #45a049; }
        a { display: block; text-align: center; margin-top: 20px; color: #4CAF50; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Preview External Content</h1>
        <p>Enter the URL you wish to preview:</p>
        <form action="/preview" method="get">
            <input type="text" name="url" placeholder="http://example.com" required />
            <input type="submit" value="Preview" />
        </form>
        <a href="/dashboard">Back to Dashboard</a>
    </div>
</body>
</html>
'''

transfer_html = '''
<!DOCTYPE html>
<html>
<head>
    <title>Secure National Bank - Transfer Funds</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f2f2f2; }
        .container { width: 600px; margin: 50px auto; background-color: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); text-align: center; }
        h1 { color: #333; margin-bottom: 20px; }
        p { font-size: 18px; }
        a { color: #4CAF50; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Transfer Funds</h1>
        <p>Online transfers are currently under maintenance.</p>
        <p>Please visit a branch or try again later.</p>
        <a href="/dashboard">Back to Dashboard</a>
    </div>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(homepage_html)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    # Fake authentication for demonstration purposes
    if username == 'user' and password == 'pass':
        session['username'] = username
        return redirect(url_for('dashboard'))
    else:
        error = "Invalid credentials. Please try again."
        return render_template_string(homepage_html, error=error)

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template_string(dashboard_html, username=session['username'])
    else:
        return redirect(url_for('home'))

@app.route('/preview-form')
def preview_form():
    if 'username' in session:
        return render_template_string(preview_form_html)
    else:
        return redirect(url_for('home'))

@app.route('/preview')
def preview():
    if 'username' not in session:
        return redirect(url_for('home'))
    url = request.args.get('url')
    if url:
        try:
            # SSRF vulnerability
            response = requests.get(url)
            return render_template_string('''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Preview of {{ url }}</title>
                <style>
                    body { font-family: Arial, sans-serif; background-color: #f2f2f2; }
                    .container { width: 800px; margin: 50px auto; background-color: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); }
                    h1 { text-align: center; color: #333; margin-bottom: 20px; }
                    pre { background-color: #eef; padding: 20px; border-radius: 4px; white-space: pre-wrap; word-wrap: break-word; }
                    a { display: block; text-align: center; margin-top: 20px; color: #4CAF50; text-decoration: none; }
                    a:hover { text-decoration: underline; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Preview of {{ url }}</h1>
                    <pre>{{ content }}</pre>
                    <a href="/preview-form">Back</a>
                </div>
            </body>
            </html>
            ''', url=url, content=response.text)
        except Exception as e:
            return f"Error fetching the URL: {e} <br/><a href='/preview-form'>Back</a>"
    else:
        return redirect(url_for('preview_form'))

@app.route('/transfer')
def transfer():
    if 'username' in session:
        return render_template_string(transfer_html)
    else:
        return redirect(url_for('home'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)