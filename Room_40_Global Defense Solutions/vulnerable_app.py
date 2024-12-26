from flask import Flask, render_template_string, request, redirect, url_for, send_file, abort
import requests
from urllib.parse import urlparse, urljoin

app = Flask(__name__)

# Templates as strings
index_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Global Defense Solutions</title>
    <style>
    /* Add some attractive CSS styles */
    body { font-family: Arial, sans-serif; background-color: #f8f9fa; margin: 0; padding: 0; }
    header { background-color: #343a40; color: white; padding: 20px; text-align: center; }
    nav { background-color: #495057; color: white; padding: 10px; }
    nav a { color: white; margin: 0 10px; text-decoration: none; }
    main { padding: 20px; }
    footer { background-color: #343a40; color: white; padding: 10px; text-align: center; position: fixed; bottom: 0; width: 100%; }
    </style>
</head>
<body>
    <header>
        <h1>Global Defense Solutions</h1>
        <p>Innovating Defense Technologies for a Safer World</p>
    </header>
    <nav>
        <a href="/">Home</a>
        <a href="/about">About Us</a>
        <a href="/careers">Careers</a>
        <a href="/get_resource_demo">Resources</a>
    </nav>
    <main>
        <h2>Welcome to Global Defense Solutions</h2>
        <p>At Global Defense Solutions, we are committed to advancing defense technologies to protect nations and their people.</p>
    </main>
    <footer>
        &copy; 2023 Global Defense Solutions. All rights reserved.
    </footer>
</body>
</html>
'''

get_resource_demo_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secure Resources - Global Defense Solutions</title>
    <style>
    /* CSS styles */
    body { font-family: Arial, sans-serif; background-color: #f8f9fa; margin: 0; padding: 0; }
    header { background-color: #343a40; color: white; padding: 20px; text-align: center; }
    nav { background-color: #495057; color: white; padding: 10px; }
    nav a { color: white; margin: 0 10px; text-decoration: none; }
    main { padding: 20px; }
    footer { background-color: #343a40; color: white; padding: 10px; text-align: center; position: fixed; bottom: 0; width: 100%; }
    form { margin-top: 20px; }
    label { display: block; margin-bottom: 5px; }
    input { padding: 5px; width: 300px; }
    button { padding: 5px 10px; margin-top: 10px; }
    </style>
</head>
<body>
    <header>
        <h1>Secure Resources - Global Defense Solutions</h1>
    </header>
    <nav>
        <a href="/">Home</a>
        <a href="/about">About Us</a>
        <a href="/careers">Careers</a>
        <a href="/get_resource_demo">Resources</a>
    </nav>
    <main>
        <h2>Access Secure Resources</h2>
        <p>Please enter your access token to retrieve the resource.</p>
        <form action="/get_resource" method="get">
            <label for="token">Access Token:</label>
            <input type="text" id="token" name="token" required>
            <br>
            <button type="submit">Get Resource</button>
        </form>
    </main>
    <footer>
        &copy; 2023 Global Defense Solutions. All rights reserved.
    </footer>
</body>
</html>
'''

def simple_encrypt(s):
    key = 'defense'
    return ''.join([chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(s)])

def simple_decrypt(s):
    return simple_encrypt(s)  # XORing twice gives the original

@app.route('/')
def index():
    return render_template_string(index_html)

@app.route('/get_resource_demo')
def get_resource_demo():
    return render_template_string(get_resource_demo_html)

@app.route('/get_resource')
def get_resource():
    token = request.args.get('token', '')
    if not token:
        return 'Token is required', 400
    try:
        url = simple_decrypt(token)
        # Perform some checks on the URL
        # For demonstration, we allow URLs starting with 'https://trustedserver.com/'
        if not url.startswith('https://trustedserver.com/'):
            return 'Invalid URL', 400
        # Fetch the content
        resp = requests.get(url)
        return resp.content, resp.status_code, resp.headers.items()
    except Exception as e:
        return 'An error occurred', 500

# Placeholders for other routes
@app.route('/about')
def about():
    return '<h1>About Global Defense Solutions</h1><p>Our mission is to innovate...</p>'

@app.route('/careers')
def careers():
    return '<h1>Careers at Global Defense Solutions</h1><p>Join our team of experts...</p>'

if __name__ == '__main__':
    app.run(debug=True)