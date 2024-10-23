from flask import Flask, request, render_template_string, redirect, url_for
import requests
import re

app = Flask(__name__)

# HTML Template with a narrative and colorful styling
html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>The Odyssey of Information</title>
    <style>
        body {
            background-color: #f0f5f9;
            font-family: 'Courier New', monospace;
            color: #333;
        }
        .header {
            background-color: #6d7fcc;
            color: white;
            padding: 10px;
            text-align: center;
        }
        .container {
            width: 80%;
            margin: 20px auto;
            padding: 20px;
            background-color: #dde1e7;
            border: 2px solid #6d7fcc;
            border-radius: 10px;
        }
        .button {
            padding: 10px 20px;
            color: white;
            background-color: #619b8a;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }
        .button:hover {
            background-color: #517d71;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>The Odyssey of Information</h1>
        <p>An ancient scroll holds secrets beyond the realms, guarded by the elusive Web Sphinx.</p>
    </div>
    <div class="container">
        <h2>Welcome, Intrepid Adventurer!</h2>
        <p>In the hidden corners of the internet lies an ancient wisdom. To unveil these secrets, you must access the Sanctum of Oracle via its mystical gateway.</p>
        <p>Your task is to provide the location of the sacred text. Remember, only the true path shall give you the insight you seek.</p>
        <form method="POST" action="{{ url_for('gateway') }}">
            <input type="text" name="url" placeholder="Enter the mystical gateway URL" style="width: 70%;">
            <button type="submit" class="button">Traverse</button>
        </form>
    </div>
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def gateway():
    if request.method == 'POST':
        url = request.form.get('url', '')
        
        if is_url_safe(url):
            try:
                response = requests.get(url)
                return f"<pre>{response.text}</pre>"
            except requests.exceptions.RequestException as e:
                return f"An error occurred while traversing: {e}"
        else:
            return "Unworthy path! The Sphinx denies your query."

    return render_template_string(html_template)

def is_url_safe(url):
    # A simplistic check to prevent localhost access, which users may try to exploit in SSRF
    blacklist_patterns = [
        r'localhost',  # localhost
        r'127\.0\.0\.1',  # loopback IPv4
        r'::1',  # loopback IPv6
        r'192\.168\.\d+\.\d+',  # local network IPv4
        r'10\.\d+\.\d+\.\d+',  # private network IPv4
        r'172\.1[6-9]\.\d+\.\d+',  # other private network IPv4
        r'172\.2[0-9]\.\d+\.\d+',  # other private network IPv4
        r'172\.3[0-1]\.\d+\.\d+'   # other private network IPv4
    ]
    
    # Compile regex patterns and check if any matches the URL
    for pattern in blacklist_patterns:
        if re.search(pattern, url):
            return False
    return True

if __name__ == '__main__':
    app.run(debug=True)