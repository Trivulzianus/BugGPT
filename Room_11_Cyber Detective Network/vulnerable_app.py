from flask import Flask, request, render_template_string, jsonify
import requests
import re

app = Flask(__name__)

# Template for the narrative web page with an SSRF vulnerability

narrative_page = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cyber Detective Network</title>
    <style>
        body {
            font-family: 'Courier New', monospace;
            background-color: #111;
            color: #eee;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            padding: 20px;
            flex-direction: column;
            text-align: center;
        }
        h1 {
            color: #0f0;
        }
        p {
            max-width: 600px;
        }
        .control-panel {
            background-color: #222;
            padding: 20px;
            border-radius: 10px;
            margin-top: 20px;
        }
        .control-panel input, .control-panel button {
            margin-top: 10px;
            padding: 10px;
            width: 300px;
        }
        .alert {
            color: red;
        }
        a {
            color: #00f;
        }
    </style>
</head>
<body>
    <h1>Welcome to the Cyber Detective Network</h1>
    <p>You are a detective investigating a secretive organization communicating through hidden tunnels on the web. Use your skills to probe and discover their hidden message. Be mindful of the organization's proxies!</p>
    <div class="control-panel">
        <h2>Network Tunnel Scanner</h2>
        <p>Enter a URL below to scan:</p>
        <form method="post">
            <input type="text" name="url" placeholder="http://example.com">
            <button type="submit">Scan</button>
        </form>
        {% if error %}
            <p class="alert">{{ error }}</p>
        {% endif %}
        {% if content %}
            <h3>Scan Result:</h3>
            <pre>{{ content }}</pre>
        {% endif %}
    </div>
    <p>Cyber Detective Network ©2023 - <a href="/">Home</a></p>
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def index():
    error = None
    content = None
    if request.method == 'POST':
        url = request.form.get('url')
        if url:
            if re.match(r'^(http|https)://', url):
                try:
                    # SSRF vulnerability - making a server-side request with the given URL
                    response = requests.get(url)
                    content = response.text[:200]  # Limit the output for display purposes
                except Exception as e:
                    error = "An error occurred while scanning the URL. Please try again."
            else:
                error = "Invalid URL format. Please enter a valid URL starting with http:// or https://."
        else:
            error = "No URL provided. Please enter a URL to scan."
    return render_template_string(narrative_page, error=error, content=content)

if __name__ == '__main__':
    app.run(debug=True)