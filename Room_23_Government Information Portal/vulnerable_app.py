from flask import Flask, request, render_template_string
import requests
import re

# Create the Flask application
app = Flask(__name__)

# Route for the main page
@app.route('/', methods=['GET', 'POST'])
def index():
    error = None
    content = None
    url = None
    if request.method == 'POST':
        url = request.form.get('url')
        if url:
            # Implement simple validation to prevent accessing internal resources
            # This validation is intentionally weak for educational purposes
            if re.match(r'^https?://', url):
                try:
                    # Fetch content from the provided URL
                    response = requests.get(url, timeout=5)
                    content = response.text
                except Exception as e:
                    error = 'An error occurred while fetching the URL.'
            else:
                error = 'Invalid URL format. Please include http:// or https://'
        else:
            error = 'Please enter a URL.'

    # Render the HTML template with dynamic content
    return render_template_string("""
<!DOCTYPE html>
<html>
<head>
    <title>Government Information Portal</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; background-color: #f8f9fa;}
        header { background-color: #004085; color: white; padding: 20px;}
        nav { background-color: #e2e3e5; padding: 10px;}
        nav a { margin: 0 15px; color: #004085; text-decoration: none;}
        nav a:hover { text-decoration: underline;}
        .container { padding: 20px;}
        footer { background-color: #004085; color: white; text-align: center; padding: 10px; position: fixed; bottom: 0; width: 100%;}
        .error { color: red; }
        .content { background-color: white; padding: 20px; border-radius: 5px;}
    </style>
</head>
<body>
    <header>
        <h1>National Government Information Portal</h1>
        <p>Your gateway to all government services and information</p>
    </header>
    <nav>
        <a href="/">Home</a>
        <a href="#">About Us</a>
        <a href="#">Departments</a>
        <a href="#">Services</a>
        <a href="#">Contact</a>
    </nav>
    <div class="container">
        <h2>External Resource Viewer</h2>
        <p>Enter the URL of the external resource you wish to access:</p>
        <form method="post">
            <input type="text" name="url" placeholder="http://example.com" size="50" value="{{ url if url }}">
            <button type="submit">Fetch Content</button>
        </form>
        {% if error %}
            <p class="error">{{ error }}</p>
        {% endif %}
        {% if content %}
            <h3>Content from {{ url }}:</h3>
            <div class="content">
                {{ content }}
            </div>
        {% endif %}
    </div>
    <footer>
        &copy; 2023 National Government Portal. All rights reserved.
    </footer>
</body>
</html>
""", error=error, content=content, url=url)

if __name__ == '__main__':
    app.run(debug=True)