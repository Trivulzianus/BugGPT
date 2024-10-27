from flask import Flask, request, render_template_string

app = Flask(__name__)

# HTML template for the web page
html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>Global Bank - Secure Online Banking</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; }
        .header { background-color: #004080; color: #ffffff; padding: 20px; text-align: center; }
        .nav { overflow: hidden; background-color: #333; }
        .nav a { float: left; display: block; color: #f2f2f2; text-align: center;
                 padding: 14px 16px; text-decoration: none; }
        .nav a:hover { background-color: #ddd; color: black; }
        .content { padding: 20px; }
        .footer { background-color: #004080; color: #ffffff; padding: 10px; text-align: center; }
        .alert { color: red; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Global Bank</h1>
        <p>Your Trusted Partner in Banking</p>
    </div>
    <div class="nav">
        <a href="/">Home</a>
        <a href="/accounts">Accounts</a>
        <a href="/loans">Loans</a>
        <a href="/contact">Contact Us</a>
    </div>
    <div class="content">
        {% if message %}
            <p class="alert">{{ message }}</p>
        {% endif %}
        <h2>Welcome to Global Bank</h2>
        <p>Experience world-class banking services tailored to your needs.</p>
        <form action="/" method="GET">
            <label for="search">Search our site:</label>
            <input type="text" id="search" name="query" placeholder="Enter your search term">
            <input type="submit" value="Search">
        </form>
    </div>
    <div class="footer">
        <p>&copy; 2023 Global Bank. All rights reserved.</p>
    </div>
</body>
</html>
"""

@app.route('/', methods=['GET'])
def home():
    # Get the query parameter from the URL
    query = request.args.get('query', '')
    message = ''
    if query:
        # Vulnerable to reflected XSS
        message = f'You searched for "{query}"'
    return render_template_string(html_template, message=message)

if __name__ == "__main__":
    app.run(debug=True)