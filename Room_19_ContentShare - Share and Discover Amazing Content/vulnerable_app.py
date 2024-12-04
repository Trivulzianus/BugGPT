from flask import Flask, request, render_template_string

app = Flask(__name__)

# HTML templates
INDEX_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>ContentShare - Share and Discover Amazing Content</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f2f2f2;
            margin: 0;
            padding: 0;
        }
        header {
            background-color: #0073e6;
            color: white;
            padding: 20px;
        }
        h1 {
            margin: 0;
        }
        .container {
            padding: 20px;
        }
        form {
            margin-top: 20px;
        }
        input[type=text] {
            width: 400px;
            padding: 10px;
            font-size: 16px;
        }
        input[type=submit] {
            padding: 10px 15px;
            font-size: 16px;
        }
    </style>
</head>
<body>
    <header>
        <h1>ContentShare</h1>
    </header>
    <div class="container">
        <p>Share your favorite articles and content with the world. Simply provide a link to the content, and we'll display it here for everyone to enjoy!</p>
        <form action="/submit" method="post">
            <label for="url"><strong>Content URL:</strong></label><br>
            <input type="text" id="url" name="url" placeholder="Enter a valid URL"><br><br>
            <input type="submit" value="Share Content">
        </form>
    </div>
</body>
</html>
'''

CONTENT_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>ContentShare - Shared Content</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #ffffff;
            margin: 0;
            padding: 0;
        }
        header {
            background-color: #0073e6;
            color: white;
            padding: 20px;
        }
        .container {
            padding: 20px;
        }
        .content {
            border: 1px solid #cccccc;
            padding: 15px;
            background-color: #f9f9f9;
        }
        a {
            color: #0073e6;
        }
    </style>
</head>
<body>
    <header>
        <h1>ContentShare</h1>
    </header>
    <div class="container">
        <h2>Shared Content</h2>
        <div class="content">
            {{ content | safe }}
        </div><br>
        <a href="/">Go back</a>
    </div>
</body>
</html>
'''

def is_private_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except:
        return False

def is_valid_url(url):
    # Allow only HTTP and HTTPS protocols
    if not re.match(r'^https?://', url):
        return False
    
    # Disallow private IP ranges and localhost
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname

        # Check for localhost and loopback addresses
        if hostname in ['localhost', '127.0.0.1']:
            return False

        # Resolve hostname to IP
        ip = socket.gethostbyname(hostname)

        # Check if IP is in private range
        if is_private_ip(ip):
            return False

    except:
        return False

    return True

def fetch_content(url):
    # Fetch the content with a custom User-Agent
    headers = {'User-Agent': 'ContentShareBot/1.0'}

    response = requests.get(url, headers=headers, timeout=5)

    if response.status_code != 200:
        raise Exception(f"Received status code {response.status_code}")

    return response.text

@app.route('/')
def index():
    return render_template_string(INDEX_HTML)

@app.route('/submit', methods=['POST'])
def submit():
    url = request.form.get('url')

    # Validate the URL
    if not is_valid_url(url):
        return "Invalid URL provided.", 400

    # Fetch content from the URL
    try:
        content = fetch_content(url)
    except Exception as e:
        return f"Error fetching the URL: {str(e)}", 500

    # Render the content in the template
    return render_template_string(CONTENT_TEMPLATE, content=content)

if __name__ == '__main__':
    app.run(host='0.0.)