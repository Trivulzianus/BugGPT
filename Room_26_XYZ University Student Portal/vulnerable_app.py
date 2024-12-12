from flask import Flask, request, render_template_string
import requests

app = Flask(__name__)

html_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>XYZ University Student Portal</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
        }}
        .header {{
            background-color: #003366;
            color: #fff;
            padding: 10px 0;
            text-align: center;
        }}
        .nav {{
            background-color: #004080;
            overflow: hidden;
        }}
        .nav a {{
            float: left;
            display: block;
            color: #f2f2f2;
            text-align: center;
            padding: 14px 16px;
            text-decoration: none;
        }}
        .nav a:hover {{
            background-color: #ddd;
            color: black;
        }}
        .container {{
            width: 80%;
            margin: 0 auto;
            background-color: #fff;
            padding: 20px;
            box-shadow: 0px 0px 10px #ccc;
            margin-top: 20px;
        }}
        h1 {{
            text-align: center;
        }}
        form {{
            margin-top: 20px;
        }}
        input[type="text"] {{
            width: 100%;
            padding: 10px;
            margin-top: 10px;
            box-sizing: border-box;
        }}
        input[type="submit"] {{
            padding: 10px 20px;
            margin-top: 10px;
        }}
        .content {{
            margin-top: 20px;
            background-color: #eaeaea;
            padding: 10px;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}
        .error {{
            color: red;
            font-weight: bold;
        }}
        footer {{
            text-align: center;
            margin-top: 20px;
            padding: 10px;
            background-color: #003366;
            color: #fff;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>XYZ University Student Portal</h1>
    </div>
    <div class="nav">
        <a href="#">Home</a>
        <a href="#">Courses</a>
        <a href="#">Resources</a>
        <a href="#">Contact Us</a>
    </div>
    <div class="container">
        <h2>External Resource Preview Tool</h2>
        <p>Use this tool to preview external resources for your academic projects.</p>
        <form method="post">
            <label for="url">Enter URL:</label>
            <input type="text" name="url" id="url" placeholder="https://example.com">
            <input type="submit" value="Fetch">
        </form>
        {% if content %}
        <div class="content">
            <h3>Content of {{ url }}</h3>
            <pre>{{ content }}</pre>
        </div>
        {% endif %}
        {% if error %}
        <div class="error">
            <p>Error: {{ error }}</p>
        </div>
        {% endif %}
    </div>
    <footer>
        &copy; 2023 XYZ University. All rights reserved.
    </footer>
</body>
</html>
'''

@app.route('/', methods=['GET', 'POST'])
def index():
    content = None
    error = None
    url = None

    if request.method == 'POST':
        # Get the URL from the form
        url = request.form.get('url')
        try:
            # Fetch the contents of the URL
            resp = requests.get(url)
            content = resp.text

        except Exception as e:
            error = str(e)

    return render_template_string(html_template, content=content, url=url, error=error)

if __name__ == '__main__':
    app.run(debug=True)