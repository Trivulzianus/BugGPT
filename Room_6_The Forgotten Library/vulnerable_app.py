from flask import Flask, request, render_template_string
import requests

app = Flask(__name__)

@app.route('/')
def index():
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>The Forgotten Library</title>
        <style>
            body {
                background: linear-gradient(to right, #0f2027, #203a43, #2c5364);
                color: #ffffff;
                font-family: 'Courier New', Courier, monospace;
            }
            h1 {
                text-align: center;
                margin-top: 20px;
                font-size: 3em;
            }
            p {
                text-align: center;
                font-size: 1.5em;
                max-width: 900px;
                margin: auto;
            }
            .form-container {
                display: flex;
                justify-content: center;
                margin-top: 40px;
            }
            input[type=text] {
                width: 400px;
                padding: 10px;
                font-size: 1em;
                margin-right: 10px;
            }
            input[type=submit] {
                padding: 10px 20px;
                background-color: #e63946;
                border: none;
                color: white;
                font-size: 1em;
                cursor: pointer;
            }
            input[type=submit]:hover {
                background-color: #f1faee;
                color: #e63946;
            }
            .narrative-box {
                background-color: rgba(255, 255, 255, 0.1);
                padding: 20px;
                margin-top: 50px;
                border-radius: 8px;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.3);
            }
            .result {
                text-align: center;
                margin-top: 20px;
                font-size: 1.2em;
            }
        </style>
    </head>
    <body>
        <h1>The Forgotten Library</h1>
        <div class="narrative-box">
            <p>Welcome to the Forgotten Library, a bastion of knowledge lost to time. As a seeker of hidden truths, your quest is to unlock the secrets buried within these digital archives. But beware, for the path is fraught with challenges that test your skill, wit, and resolve.</p>
        </div>
        <div class="form-container">
            <form action="/fetch" method="post">
                <input type="text" name="url" placeholder="Enter the Archive URL" required>
                <input type="submit" value="Retrieve Knowledge">
            </form>
        </div>
        {% if result %}
        <div class="result">
            <h3>Archive Response:</h3>
            <pre>{{ result }}</pre>
        </div>
        {% endif %}
    </body>
    </html>
    ''')

@app.route('/fetch', methods=['POST'])
def fetch():
    url = request.form.get('url')
    try:
        response = requests.get(url, timeout=5)
        content = response.text
    except Exception as e:
        content = "An error occurred while trying to fetch the archive: " + str(e)
    return render_template_string('''
    {% extends "index" %}
    {% block content %}
    <div class="result">
        <h3>Archive Response:</h3>
        <pre>{{ result }}</pre>
    </div>
    {% endblock %}
    ''', result=content)

if __name__ == '__main__':
    app.run(debug=True)