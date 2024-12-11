from flask import Flask, request, render_template_string
import requests

app = Flask(__name__)

@app.route('/')
def home():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Global Bank - Online Banking Portal</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background-color: #f4f4f4;
                margin: 0;
                padding: 0;
            }
            header {
                background-color: #2c3e50;
                color: #ecf0f1;
                padding: 20px 0;
            }
            header h1 {
                text-align: center;
                margin: 0;
            }
            nav {
                background-color: #34495e;
                overflow: hidden;
            }
            nav a {
                float: left;
                display: block;
                color: #ecf0f1;
                text-align: center;
                padding: 14px 16px;
                text-decoration: none;
            }
            nav a:hover {
                background-color: #1abc9c;
                color: white;
            }
            .container {
                width: 80%;
                margin: auto;
                overflow: hidden;
            }
            #showcase {
                background: url('https://www.examplebank.com/banner.jpg') no-repeat center center/cover;
                color: #ffffff;
                height: 400px;
                text-align: center;
                padding-top: 100px;
            }
            #showcase h2 {
                font-size: 55px;
                margin-bottom: 10px;
            }
            #main {
                padding: 20px;
                background: #ecf0f1;
            }
            #main h3 {
                text-align: center;
            }
            footer {
                background-color: #2c3e50;
                color: #ecf0f1;
                text-align: center;
                padding: 20px 0;
                margin-top: 20px;
            }
            .status-form {
                text-align: center;
                margin-top: 30px;
            }
            .status-form input[type="text"] {
                padding: 10px;
                width: 300px;
                font-size: 16px;
            }
            .status-form input[type="submit"] {
                padding: 10px 20px;
                font-size: 16px;
                background-color: #1abc9c;
                border: none;
                color: #fff;
                cursor: pointer;
            }
            .status-form input[type="submit"]:hover {
                background-color: #16a085;
            }
        </style>
    </head>
    <body>
        <header>
            <h1>Global Bank</h1>
        </header>
        <nav>
            <a href="/">Home</a>
            <a href="/accounts">Accounts</a>
            <a href="/loans">Loans</a>
            <a href="/investments">Investments</a>
            <a href="/contact">Contact Us</a>
        </nav>
        <div id="showcase">
            <h2>Welcome to Global Bank</h2>
            <p>Your trusted partner in financial success</p>
        </div>
        <div id="main" class="container">
            <h3>Check ATM and Branch Status</h3>
            <p>Enter the city name to view the operational status of our ATMs and branches.</p>
            <div class="status-form">
                <form action="/status" method="GET">
                    <input type="text" name="city" placeholder="Enter city name" required>
                    <input type="submit" value="Check Status">
                </form>
            </div>
        </div>
        <footer>
            &copy; 2023 Global Bank. All Rights Reserved.
        </footer>
    </body>
    </html>
    ''')

@app.route('/status')
def status():
    city = request.args.get('city')
    if city:
        # Potential SSRF vulnerability here due to improper input validation
        api_url = f'http://api.globalbank.com/status/{city}'
        try:
            response = requests.get(api_url)
            content = response.text
        except Exception as e:
            content = f"Error fetching status: {e}"
        return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Status for {{ city }} - Global Bank</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #ecf0f1;
                    margin: 0;
                    padding: 0;
                }
                header {
                    background-color: #2c3e50;
                    color: #ecf0f1;
                    padding: 20px 0;
                }
                header h1 {
                    text-align: center;
                    margin: 0;
                }
                .container {
                    width: 80%;
                    margin: auto;
                    overflow: hidden;
                    padding: 20px;
                    background-color: #fff;
                    margin-top: 20px;
                }
                footer {
                    background-color: #2c3e50;
                    color: #ecf0f1;
                    text-align: center;
                    padding: 20px 0;
                    margin-top: 20px;
                }
                a {
                    color: #1abc9c;
                    text-decoration: none;
                }
            </style>
        </head>
        <body>
            <header>
                <h1>Global Bank</h1>
            </header>
            <div class="container">
                <h2>Status for {{ city }}</h2>
                <div>
                    {{ content | safe }}
                </div>
                <p><a href="/">Back to Home</a></p>
            </div>
            <footer>
                &copy; 2023 Global Bank. All Rights Reserved.
            </footer>
        </body>
        </html>
        ''', city=city, content=content)
    else:
        return "Please provide a city name."

if __name__ == '__main__':
    app.run(debug=True)