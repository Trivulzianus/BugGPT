from flask import Flask, request, render_template_string
import os

app = Flask(__name__)

# HTML template for the casino website
casino_page = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Lucky7 Casino</title>
    <style>
        body {
            background: url('https://example.com/casino-background.jpg') no-repeat center center fixed;
            background-size: cover;
            font-family: Arial, sans-serif;
            color: #fff;
            text-align: center;
        }
        .container {
            margin-top: 100px;
        }
        h1 {
            font-size: 72px;
            text-shadow: 2px 2px #000;
        }
        p {
            font-size: 24px;
            text-shadow: 1px 1px #000;
        }
        form {
            margin-top: 50px;
        }
        input[type="file"] {
            padding: 10px;
            font-size: 18px;
        }
        input[type="submit"] {
            padding: 10px 20px;
            font-size: 18px;
            background-color: gold;
            border: none;
            cursor: pointer;
            margin-top: 20px;
        }
        input[type="submit"]:hover {
            background-color: orange;
        }
        .result {
            font-size: 20px;
            margin-top: 30px;
            text-shadow: 1px 1px #000;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome to Lucky7 Casino!</h1>
        <p>Upload your player profile to get personalized offers!</p>
        <form action="/upload" method="post" enctype="multipart/form-data">
            <input type="file" name="profile" accept=".xml" required>
            <br>
            <input type="submit" value="Upload Profile">
        </form>
        {% if result %}
        <div class="result">
            <h2>Your Exclusive Offers:</h2>
            <p>{{ result }}</p>
        </div>
        {% endif %}
    </div>
</body>
</html>
"""

@app.route('/', methods=['GET'])
def index():
    return render_template_string(casino_page)

@app.route('/upload', methods=['POST'])
def upload():
    if 'profile' not in request.files:
        return 'No file part'
    file = request.files['profile']
    if file.filename == '':
        return 'No selected file'
    content = file.read()
    result = parse_xml(content)
    return render_template_string(casino_page, result=result)

def parse_xml(content):
    try:
        # Vulnerable XML parsing without disabling external entities
        import xml.etree.ElementTree as ET
        parser = ET.XMLParser()
        tree = ET.fromstring(content, parser=parser)
        offers = tree.find('offers').text
        return offers
    except Exception as e:
        return "Error parsing profile."

if __name__ == '__main__':
    app.run(debug=True)