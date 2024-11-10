from flask import Flask, render_template_string, request, redirect, url_for
import requests
from urllib.parse import urlparse
import re

app = Flask(__name__)

# HTML Templates

home_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Secure Bank - Home</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f2f2f2; }
        .container { width: 80%; margin: auto; padding: 20px; background-color: #fff; }
        h1 { text-align: center; color: #333; }
        .nav { text-align: center; margin-bottom: 20px; }
        .nav a { margin: 0 15px; text-decoration: none; color: #007bff; }
        .nav a:hover { text-decoration: underline; }
        p { text-align: center; font-size: 1.2em; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome to Secure Bank</h1>
        <div class="nav">
            <a href="{{ url_for('home') }}">Home</a>
            <a href="{{ url_for('upload_document') }}">Upload Document</a>
            <a href="{{ url_for('contact') }}">Contact Us</a>
        </div>
        <p>Your trusted partner in financial services.</p>
    </div>
</body>
</html>
'''

upload_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Secure Bank - Upload Document</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f2f2f2; }
        .container { width: 80%; margin: auto; padding: 20px; background-color: #fff; }
        h1 { text-align: center; color: #333; }
        .nav { text-align: center; margin-bottom: 20px; }
        .nav a { margin: 0 15px; text-decoration: none; color: #007bff; }
        .nav a:hover { text-decoration: underline; }
        form { text-align: center; }
        label { font-size: 1.1em; }
        input[type="text"] { padding: 5px; font-size: 1em; width: 60%; }
        input[type="submit"] { padding: 5px 15px; font-size: 1em; }
        pre { background-color: #eee; padding: 10px; overflow-x: auto; }
        p { text-align: center; font-size: 1.2em; color: red; }
        h2 { text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Upload Your Document</h1>
        <div class="nav">
            <a href="{{ url_for('home') }}">Home</a>
            <a href="{{ url_for('upload_document') }}">Upload Document</a>
            <a href="{{ url_for('contact') }}">Contact Us</a>
        </div>
        <form method="post">
            <label for="doc_url">Document URL:</label><br><br>
            <input type="text" id="doc_url" name="doc_url"><br><br>
            <input type="submit" value="Upload">
        </form>
        {% if error %}
            <p>{{ error }}</p>
        {% endif %}
        {% if content %}
            <h2>Document Preview:</h2>
            <pre>{{ content }}</pre>
        {% endif %}
    </div>
</body>
</html>
'''

contact_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Secure Bank - Contact Us</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f2f2f2; }
        .container { width: 80%; margin: auto; padding: 20px; background-color: #fff; }
        h1 { text-align: center; color: #333; }
        .nav { text-align: center; margin-bottom: 20px; }
        .nav a { margin: 0 15px; text-decoration: none; color: #007bff; }
        .nav a:hover { text-decoration: underline; }
        p { font-size: 1.1em; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Contact Us</h1>
        <div class="nav">
            <a href="{{ url_for('home') }}">Home</a>
            <a href="{{ url_for('upload_document') }}">Upload Document</a>
            <a href="{{ url_for('contact') }}">Contact Us</a>
        </div>
        <p>Email: support@securebank.example.com</p>
        <p>Phone: +1-555-0123456</p>
        <p>Address: 123 Secure Lane, Safe City, Country</p>
    </div>
</body>
</html>
'''

# Function to validate URLs
def is_safe_url(url):
    parsed_url = urlparse(url)
    if parsed_url.scheme not in ('http', 'https'):
        return False

    netloc = parsed_url.netloc

    # Extract hostname (handles cases like user@hostname)
    if '@' in netloc:
        netloc = netloc.rsplit('@', 1)[1]

    host = netloc.split(':')[0]

    # Disallow localhost and loopback addresses
    if host.lower() == 'localhost' or host.startswith('127.') or host.startswith('0.'):
        return False

    # Regular expression patterns for IP addresses
    ipv4_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    ipv6_pattern = re.compile(r'^\[?[0-9a-fA-F:]+\]?$')

    if ipv4_pattern.match(host):
        # Convert IP to integer and check for private ranges
        octets = host.split('.')
        ip_int = (int(octets[0]) << 24) + (int(octets[1]) << 16) + (int(octets[2]) << 8) + int(octets[3])
        # Private IP ranges
        private_ranges = [
            (2130706432, 2130771967),   # 127.0.0.0 - 127.255.255.255 (Loopback)
            (167772160, 184549375),     # 10.0.0.0 - 10.255.255.255
            (2886729728, 2887778303),   # 172.16.0.0 - 172.31.255.255
            (3232235520, 3232301055),   # 192.168.0.0 - 192.168.255.255
        ]
        for start, end in private_ranges:
            if start <= ip_int <= end:
                return False

    elif ipv6_pattern.match(host):
        # For simplicity, disallow all IPv6 addresses
        return False

    # Disallow internal domains
    if host.endswith('.internal') or host.endswith('.localdomain'):
        return False

    return True

# Routes

@app.route('/')
def home():
    return render_template_string(home_template)

@app.route('/upload', methods=['GET', 'POST'])
def upload_document():
    error = None
    content = None
    if request.method == 'POST':
        doc_url = request.form.get('doc_url')
        if doc_url:
            try:
                # Validate the URL
                if not is_safe_url(doc_url):
                    error = "Invalid URL provided."
                else:
                    # Fetch the document
                    headers = {'User-Agent': 'SecureBankBot/1.0'}
                    resp = requests.get(doc_url, headers=headers, timeout=5)
                    if resp.status_code == 200:
                        # Limit content size
                        if len(resp.content) < 5000:
                            content = resp.text
                        else:
                            error = "Document too large."
                    else:
                        error = "Unable to fetch the document."
            except Exception as e:
                error = "An error occurred while fetching the document."
        else:
            error = "Please provide a document URL."
    return render_template_string(upload_template, error=error, content=content)

@app.route('/contact')
def contact():
    return render_template_string(contact_template)

if __name__ == '__main__':
    app.run(debug=True)