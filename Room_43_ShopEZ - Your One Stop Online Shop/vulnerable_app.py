from flask import Flask, request, render_template_string
import os
from lxml import etree

app = Flask(__name__)

homepage_html = '''
<!DOCTYPE html>
<html>
<head>
    <title>ShopEZ - Your One Stop Online Shop</title>
    <style>
        /* CSS styles to make it look professional */
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f7f7f7;
        }
        .header {
            background-color: #ffffff;
            padding: 20px;
        }
        .header h1 {
            margin: 0;
        }
        .nav {
            background-color: #333333;
            overflow: hidden;
        }
        .nav a {
            float: left;
            color: #f2f2f2;
            display: block;
            padding: 14px 16px;
            text-decoration: none;
        }
        .nav a:hover {
            background-color: #dddddd;
            color: black;
        }
        .content {
            padding: 20px;
            min-height: 400px;
        }
        .footer {
            background-color: #333333;
            color: #ffffff;
            text-align: center;
            padding: 10px;
            position: relative;
            bottom: 0;
            width:100%;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>ShopEZ</h1>
        <p>Your One Stop Online Shop</p>
    </div>
    <div class="nav">
        <a href="/">Home</a>
        <a href="/order">Order</a>
        <a href="/contact">Contact Us</a>
    </div>
    <div class="content">
        <h2>Welcome to ShopEZ!</h2>
        <p>We offer the best products at the best prices.</p>
        <p>Browse our categories and discover amazing deals.</p>
        <ul>
            <li>Electronics</li>
            <li>Fashion</li>
            <li>Home Appliances</li>
            <li>Books</li>
            <li>More...</li>
        </ul>
    </div>
    <div class="footer">
        &copy; 2023 ShopEZ
    </div>
</body>
</html>
'''

order_form_html = '''
<!DOCTYPE html>
<html>
<head>
    <title>ShopEZ - Place Your Order</title>
    <style>
        /* CSS styles for the order form */
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f7f7f7;
        }
        .header {
            background-color: #ffffff;
            padding: 20px;
        }
        .header h1 {
            margin: 0;
        }
        .nav {
            background-color: #333333;
            overflow: hidden;
        }
        .nav a {
            float: left;
            color: #f2f2f2;
            display: block;
            padding: 14px 16px;
            text-decoration: none;
        }
        .nav a:hover {
            background-color: #dddddd;
            color: black;
        }
        .content {
            padding: 20px;
            min-height: 400px;
        }
        form {
            background-color: #ffffff;
            padding: 20px;
            border-radius: 5px;
        }
        textarea {
            width: 100%;
            height: 200px;
            resize: vertical;
        }
        input[type=submit] {
            padding: 10px 20px;
            background-color: #333333;
            color: #ffffff;
            border: none;
            cursor: pointer;
        }
        input[type=submit]:hover {
            background-color: #555555;
        }
        .footer {
            background-color: #333333;
            color: #ffffff;
            text-align: center;
            padding: 10px;
            position: relative;
            bottom: 0;
            width:100%;
        }
        .message {
            background-color: #e7f3fe;
            border-left: 6px solid #2196F3;
            padding: 10px;
        }
        .error {
            background-color: #f8d7da;
            border-left: 6px solid #f44336;
            padding: 10px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>ShopEZ</h1>
        <p>Your One Stop Online Shop</p>
    </div>
    <div class="nav">
        <a href="/">Home</a>
        <a href="/order">Order</a>
        <a href="/contact">Contact Us</a>
    </div>
    <div class="content">
        <h2>Place Your Order</h2>
        <p>Please paste your order details in XML format below:</p>
        <form method="post">
            <textarea name="orderxml">&lt;?xml version="1.0" encoding="UTF-8"?&gt;
&lt;order&gt;
    &lt;item&gt;Sample Product&lt;/item&gt;
    &lt;quantity&gt;1&lt;/quantity&gt;
&lt;/order&gt;</textarea><br><br>
            <input type="submit" value="Submit Order">
        </form>
    </div>
    <div class="footer">
        &copy; 2023 ShopEZ
    </div>
</body>
</html>
'''

order_response_html = '''
<!DOCTYPE html>
<html>
<head>
    <title>ShopEZ - Order Confirmation</title>
    <style>
        /* CSS styles for the response page */
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f7f7f7;
        }
        .header {
            background-color: #ffffff;
            padding: 20px;
        }
        .header h1 {
            margin: 0;
        }
        .nav {
            background-color: #333333;
            overflow: hidden;
        }
        .nav a {
            float: left;
            color: #f2f2f2;
            display: block;
            padding: 14px 16px;
            text-decoration: none;
        }
        .nav a:hover {
            background-color: #dddddd;
            color: black;
        }
        .content {
            padding: 20px;
            min-height: 400px;
        }
        .message {
            background-color: #e7f3fe;
            border-left: 6px solid #2196F3;
            padding: 10px;
        }
        .error {
            background-color: #f8d7da;
            border-left: 6px solid #f44336;
            padding: 10px;
        }
        .footer {
            background-color: #333333;
            color: #ffffff;
            text-align: center;
            padding: 10px;
            position: relative;
            bottom: 0;
            width:100%;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>ShopEZ</h1>
        <p>Your One Stop Online Shop</p>
    </div>
    <div class="nav">
        <a href="/">Home</a>
        <a href="/order">Order</a>
        <a href="/contact">Contact Us</a>
    </div>
    <div class="content">
        <h2>Order Confirmation</h2>
        {% if 'Error' in response %}
            <div class="error">
                <p>{{ response }}</p>
            </div>
        {% else %}
            <div class="message">
                <p>{{ response }}</p>
            </div>
        {% endif %}
    </div>
    <div class="footer">
        &copy; 2023 ShopEZ
    </div>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(homepage_html)

@app.route('/order', methods=['GET', 'POST'])
def order():
    if request.method == 'POST':
        order_xml = request.form['orderxml']
        # Process the XML unsafely using lxml (vulnerable to XXE)
        try:
            root = etree.fromstring(order_xml)
            # Extract order details
            item = root.find('item').text
            quantity = root.find('quantity').text
            # Generate a response
            response = f'Order received: {quantity} x {item}'
        except Exception as e:
            response = f'Error processing order: {str(e)}'
        return render_template_string(order_response_html, response=response)
    else:
        return render_template_string(order_form_html)

@app.route('/contact')
def contact():
    contact_html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>ShopEZ - Contact Us</title>
        <style>
            /* CSS styles for the contact page */
            body {
                font-family: Arial, sans-serif;
                margin: 0;
                padding: 0;
                background-color: #f7f7f7;
            }
            .header {
                background-color: #ffffff;
                padding: 20px;
            }
            .header h1 {
                margin: 0;
            }
            .nav {
                background-color: #333333;
                overflow: hidden;
            }
            .nav a {
                float: left;
                color: #f2f2f2;
                display: block;
                padding: 14px 16px;
                text-decoration: none;
            }
            .nav a:hover {
                background-color: #dddddd;
                color: black;
            }
            .content {
                padding: 20px;
                min-height: 400px;
            }
            .footer {
                background-color: #333333;
                color: #ffffff;
                text-align: center;
                padding: 10px;
                position: relative;
                bottom: 0;
                width:100%;
            }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>ShopEZ</h1>
            <p>Your One Stop Online Shop</p>
        </div>
        <div class="nav">
            <a href="/">Home</a>
            <a href="/order">Order</a>
            <a href="/contact">Contact Us</a>
        </div>
        <div class="content">
            <h2>Contact Us</h2>
            <p>For inquiries, please email us at support@shopez.com or call us at 1-800-SHOPEZ.</p>
        </div>
        <div class="footer">
            &copy; 2023 ShopEZ
        </div>
    </body>
    </html>
    '''
    return render_template_string(contact_html)

if __name__ == '__main__':
    app.run(debug=True)