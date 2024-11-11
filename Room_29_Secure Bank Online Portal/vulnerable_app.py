from flask import Flask, request, render_template_string
import requests
import base64

app = Flask(__name__)

template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secure Bank Online Portal</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f7f8;
            margin: 0;
            padding: 0;
        }
        header {
            background-color: #00539C;
            color: white;
            padding: 20px;
            text-align: center;
        }
        nav {
            background-color: #003F7D;
            overflow: hidden;
        }
        nav a {
            float: left;
            display: block;
            color: #f4f7f8;
            text-align: center;
            padding: 14px 16px;
            text-decoration: none;
        }
        nav a:hover {
            background-color: #f1f1f1;
            color: #00539C;
        }
        .container {
            padding: 20px;
        }
        input[type=text] {
            width: 60%;
            padding: 12px;
            margin: 8px 0;
            box-sizing: border-box;
            border: 2px solid #ccc;
            border-radius: 4px;
        }
        input[type=submit] {
            background-color: #00539C;
            color: white;
            padding: 12px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        input[type=submit]:hover {
            background-color: #003F7D;
        }
        .error {
            color: red;
        }
        .image-container {
            margin-top: 20px;
        }
        footer {
            background-color: #00539C;
            color: white;
            text-align: center;
            padding: 10px;
            position: fixed;
            width: 100%;
            bottom: 0;
        }
        img {
            max-width: 100%;
            height: auto;
        }
    </style>
</head>
<body>
    <header>
        <h1>Secure Bank</h1>
        <p>Your Trusted Financial Partner</p>
    </header>
    <nav>
        <a href="#">Home</a>
        <a href="#">Accounts</a>
        <a href="#">Services</a>
        <a href="#">Contact Us</a>
    </nav>
    <div class="container">
        <h2>View Promotional Material</h2>
        <p>Enter the URL of our promotional image to view:</p>
        <form action="/fetch" method="post">
            <input type="text" name="url" placeholder="https://www.securebank.com/images/promo.png"><br>
            <input type="submit" value="View Image">
        </form>
        {% if error %}
            <p class="error">{{ error }}</p>
        {% endif %}
        {% if image %}
            <div class="image-container">
                <h3>Promotional Image:</h3>
                <img src="data:image/png;base64,{{ image }}" alt="Loaded Image">
            </div>
        {% endif %}
    </div>
    <footer>
        <p>&copy; 2023 Secure Bank. All rights reserved.</p>
    </footer>
</body>
</html>
'''

@app.route('/', methods=['GET'])
def index():
    return render_template_string(template)

@app.route('/fetch', methods=['POST'])
def fetch():
    url = request.form.get('url')
    try:
        response = requests.get(url)
        if 'image' in response.headers.get('Content-Type', ''):
            image_b64 = base64.b64encode(response.content).decode('utf-8')
            return render_template_string(template, image=image_b64)
        else:
            error_message = "The URL does not point to an image."
            return render_template_string(template, error=error_message)
    except Exception as e:
        error_message = "An error occurred while fetching the image."
        return render_template_string(template, error=error_message)

if __name__ == '__main__':
    app.run(debug=Fals)