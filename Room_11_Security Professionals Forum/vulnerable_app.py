from flask import Flask, request, render_template_string, redirect, url_for
import re
import socket
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

HOME_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Security Professionals Forum</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #f9f9f9;}
        h1 {color: #3366cc;}
        .thread {border-bottom: 1px solid #ccc; padding: 10px;}
        #threads {margin-bottom: 20px;}
        input[type="text"] {padding: 5px; width: 400px;}
        input[type="submit"] {padding: 5px 10px;}
    </style>
</head>
<body>
    <h1>Security Professionals Forum</h1>
    <div id="threads">
        {% for thread in threads %}
        <div class="thread">
            <h2><a href="{{ url_for('view_thread', title=thread.title) }}">{{ thread.title }}</a></h2>
            <p>by {{ thread.author }}</p>
        </div>
        {% endfor %}
    </div>
    <h3>Preview a URL</h3>
    <form action="{{ url_for('preview') }}" method="post">
        <input type="text" name="url" placeholder="Enter URL to preview">
        <input type="submit" value="Preview">
    </form>
</body>
</html>
'''

THREAD_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>{{ title }}</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #f9f9f9;}
        h1 {color: #3366cc;}
        .post {border-bottom: 1px solid #ccc; padding: 10px;}
        textarea {width: 600px;}
    </style>
</head>
<body>
    <h1>{{ title }}</h1>
    <div id="content">
        <p>{{ content }}</p>
    </div>
    <hr>
    <h3>Reply to this thread</h3>
    <form action="{{ url_for('reply', title=title) }}" method="post">
        <textarea name="message" rows="5"></textarea><br>
        <input type="submit" value="Post Reply">
    </form>
    <br>
    <a href="{{ url_for('home') }}">Back to Home</a>
</body>
</html>
'''

REPLY_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Reply Posted</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #f9f9f9;}
        h1 {color: #3366cc;}
    </style>
</head>
<body>
    <h1>Your reply has been posted to "{{ title }}"</h1>
    <div class="post">
        <p>{{ message }}</p>
    </div>
    <br>
    <a href="{{ url_for('view_thread', title=title) }}">Back to Thread</a>
</body>
</html>
'''

PREVIEW_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>URL Preview</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #f9f9f9;}
        h1 {color: #3366cc;}
        #content {border: 1px solid #ccc; padding: 10px; background-color: #fff;}
    </style>
</head>
<body>
    <h1>URL Preview</h1>
    <div id="content">
        {{ content | safe }}
    </div>
    <br>
    <a href="{{ url_for('home') }}">Back to Home</a>
</body>
</html>
'''

@app.route('/')
def home():
    threads = [
        {'title': 'Welcome to the Forum', 'author': 'Admin'},
        {'title': 'Latest Security News', 'author': 'User123'},
    ]
    return render_template_string(HOME_TEMPLATE, threads=threads)

@app.route('/thread/<title>')
def view_thread(title):
    # For simplicity, the content is static
    content = "Discussion content for {}".format(title)
    return render_template_string(THREAD_TEMPLATE, title=title, content=content)

@app.route('/reply/<title>', methods=['POST'])
def reply(title):
    message = request.form.get('message', '')
    # Display the message back to the user
    return render_template_string(REPLY_TEMPLATE, title=title, message=message)

@app.route('/preview', methods=['GET', 'POST'])
def preview():
    if request.method == 'POST':
        url = request.form.get('url', '')
        # Validate the URL
        if is_valid_url(url):
            content = fetch_url_content(url)
            return render_template_string(PREVIEW_TEMPLATE, content=content)
        else:
            return 'Invalid URL', 400
    else:
        return redirect(url_for('home'))

def is_valid_url(url):
    # Validate the URL format and ensure it's not a local or private IP
    pattern = re.compile(r'^https?://(www\.)?[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(/.*)?$')
    if pattern.match(url):
        domain = re.findall(r'https?://([^/]+)', url)[0]
        # Disallow private IP ranges
        if is_public_domain(domain):
            return True
    return False

def is_public_domain(domain):
    # Check if the domain resolves to a public IP address
    try:
        ip = socket.gethostbyname(domain)
        # Disallow localhost and private IP addresses
        private_ips = [
            re.compile(r'^127\.'),                # Loopback
            re.compile(r'^10\.'),                 # Class A private
            re.compile(r'^192\.168\.'),           # Class C private
            re.compile(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.'),  # Class B private
            re.compile(r'^0\.0\.0\.0'),           # Non-routable meta-address
        ]
        for pattern in private_ips:
            if pattern.match(ip):
                return False
        return True
    except:
        return False

def fetch_url_content(url):
    try:
        resp = requests.get(url, timeout=5)
        return resp.text
    except Exception as e:
        return "Error fetching URL: {}".format(e)

if __name__ == '__main__':
    app.run(host='0.0.)