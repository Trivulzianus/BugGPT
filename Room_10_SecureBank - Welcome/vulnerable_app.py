from flask import Flask, render_template_string, request, redirect, url_for
import requests

app = Flask(__name__)

@app.route('/', methods=['GET'])
def index():
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SecureBank - Welcome</title>
    <style>
        body {font-family: Arial, sans-serif; margin: 0; padding: 0;}
        header {background-color: #0D47A1; padding: 20px; color: white; text-align: center;}
        nav {background-color: #1976D2; padding: 10px; display: flex; justify-content: center;}
        nav a {margin: 0 15px; text-decoration: none; color: white; font-weight: bold;}
        nav a:hover {text-decoration: underline;}
        section {padding: 40px; text-align: center;}
        footer {background-color: #0D47A1; padding: 10px; color: white; text-align: center;}
        h1, h2 {margin: 0;}
        .cta-button {background-color: #2196F3; color: white; padding: 15px 25px; text-decoration: none; font-size: 18px; border-radius: 5px;}
        .cta-button:hover {background-color: #1976D2;}
    </style>
</head>
<body>
    <header>
        <h1>SecureBank Online Services</h1>
    </header>
    <nav>
        <a href="/">Home</a>
        <a href="/exchange-rates">Exchange Rates</a>
        <a href="/loans">Loans</a>
        <a href="/contact">Contact Us</a>
    </nav>
    <section>
        <h2>Welcome to SecureBank</h2>
        <p>Your trusted partner in online banking. Manage your accounts, view transactions, and explore our financial services to help you reach your goals.</p>
        <a href="/exchange-rates" class="cta-button">Check Exchange Rates</a>
    </section>
    <footer>
        &copy; 2023 SecureBank. All rights reserved.
    </footer>
</body>
</html>
    ''')

@app.route('/exchange-rates', methods=['GET', 'POST'])
def exchange_rates():
    content = ''
    if request.method == 'POST':
        url = request.form.get('url')
        try:
            resp = requests.get(url)
            content = resp.text
        except Exception as e:
            content = f"An error occurred: {e}"
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SecureBank - Exchange Rates</title>
    <style>
        body {font-family: Arial, sans-serif; margin: 0; padding: 0;}
        header {background-color: #0D47A1; padding: 20px; color: white; text-align: center;}
        nav {background-color: #1976D2; padding: 10px; display: flex; justify-content: center;}
        nav a {margin: 0 15px; text-decoration: none; color: white; font-weight: bold;}
        nav a:hover {text-decoration: underline;}
        section {padding: 40px;}
        footer {background-color: #0D47A1; padding: 10px; color: white; text-align: center;}
        h1, h2 {margin: 0;}
        .input-field {width: 80%; padding: 10px; margin: 10px 0; font-size: 16px;}
        .submit-btn {padding: 10px 20px; background-color: #2196F3; color: white; border: none; font-size: 16px; cursor: pointer; border-radius: 5px;}
        .submit-btn:hover {background-color: #1976D2;}
        .result {padding: 20px; background-color: #f1f1f1; margin-top: 20px; border-radius: 5px;}
        pre {white-space: pre-wrap; word-wrap: break-word;}
    </style>
</head>
<body>
    <header>
        <h1>SecureBank Exchange Rates</h1>
    </header>
    <nav>
        <a href="/">Home</a>
        <a href="/exchange-rates">Exchange Rates</a>
        <a href="/loans">Loans</a>
        <a href="/contact">Contact Us</a>
    </nav>
    <section>
        <h2>Get the Latest Exchange Rates</h2>
        <p>Use our exchange rate service to fetch the latest rates from your preferred financial news source.</p>
        <form method="post" action="/exchange-rates">
            <input type="text" name="url" class="input-field" placeholder="Enter source URL" required />
            <br>
            <button type="submit" class="submit-btn">Fetch Rates</button>
        </form>
        {% if content %}
        <div class="result">
            <h3>Exchange Rates Data:</h3>
            <pre>{{ content }}</pre>
        </div>
        {% endif %}
    </section>
    <footer>
        &copy; 2023 SecureBank. All rights reserved.
    </footer>
</body>
</html>
    ''', content=content)

@app.route('/loans', methods=['GET'])
def loans():
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SecureBank - Loans</title>
    <style>
        body {font-family: Arial, sans-serif; margin: 0; padding: 0;}
        header {background-color: #0D47A1; padding: 20px; color: white; text-align: center;}
        nav {background-color: #1976D2; padding: 10px; display: flex; justify-content: center;}
        nav a {margin: 0 15px; text-decoration: none; color: white; font-weight: bold;}
        nav a:hover {text-decoration: underline;}
        section {padding: 40px;}
        footer {background-color: #0D47A1; padding: 10px; color: white; text-align: center;}
        h1, h2 {margin: 0;}
        .loan-options {display: flex; justify-content: space-around; margin-top: 30px;}
        .loan-option {width: 30%; background-color: #f1f1f1; padding: 20px; border-radius: 5px;}
        .loan-option h3 {margin-top: 0;}
        .apply-btn {margin-top: 10px; display: inline-block; padding: 10px 15px; background-color: #2196F3; color: white; text-decoration: none; border-radius: 5px;}
        .apply-btn:hover {background-color: #1976D2;}
    </style>
</head>
<body>
    <header>
        <h1>SecureBank Loan Services</h1>
    </header>
    <nav>
        <a href="/">Home</a>
        <a href="/exchange-rates">Exchange Rates</a>
        <a href="/loans">Loans</a>
        <a href="/contact">Contact Us</a>
    </nav>
    <section>
        <h2>Choose the Right Loan for You</h2>
        <div class="loan-options">
            <div class="loan-option">
                <h3>Personal Loan</h3>
                <p>Flexible personal loans to meet your needs.</p>
                <a href="#" class="apply-btn">Apply Now</a>
            </div>
            <div class="loan-option">
                <h3>Home Loan</h3>
                <p>Competitive rates for your dream home.</p>
                <a href="#" class="apply-btn">Apply Now</a>
            </div>
            <div class="loan-option">
                <h3>Auto Loan</h3>
                <p>Get on the road with our auto loans.</p>
                <a href="#" class="apply-btn">Apply Now</a>
            </div>
        </div>
    </section>
    <footer>
        &copy; 2023 SecureBank. All rights reserved.
    </footer>
</body>
</html>
    ''')

@app.route('/contact', methods=['GET'])
def contact():
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SecureBank - Contact Us</title>
    <style>
        body {font-family: Arial, sans-serif; margin: 0; padding: 0;}
        header {background-color: #0D47A1; padding: 20px; color: white; text-align: center;}
        nav {background-color: #1976D2; padding: 10px; display: flex; justify-content: center;}
        nav a {margin: 0 15px; text-decoration: none; color: white; font-weight: bold;}
        nav a:hover {text-decoration: underline;}
        section {padding: 40px; text-align: center;}
        footer {background-color: #0D47A1; padding: 10px; color: white; text-align: center;}
        h1, h2 {margin: 0;}
        .contact-info {margin-top: 30px;}
        .contact-info p {margin: 5px 0;}
    </style>
</head>
<body>
    <header>
        <h1>SecureBank Contact Us</h1>
    </header>
    <nav>
        <a href="/">Home</a>
        <a href="/exchange-rates">Exchange Rates</a>
        <a href="/loans">Loans</a>
        <a href="/contact">Contact Us</a>
    </nav>
    <section>
        <h2>We'd Love to Hear From You</h2>
        <div class="contact-info">
            <p><strong>Email:</strong> support@securebank.com</p>
            <p><strong>Phone:</strong> +1 (555) 123-4567</p>
            <p><strong>Address:</strong> 123 Finance Avenue, Money City, Economy State</p>
        </div>
    </section>
    <footer>
        &copy; 2023 SecureBank. All rights reserved.
    </footer>
</body>
</html>
    ''')

if __name__ == '__main__':
    app.run(debug=True)