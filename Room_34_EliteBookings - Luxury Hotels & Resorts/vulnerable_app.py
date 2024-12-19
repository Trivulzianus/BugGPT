from flask import Flask, request, render_template_string
from lxml import etree

app = Flask(__name__)

index_page = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>EliteBookings - Luxury Hotels & Resorts</title>
    <style>
        body {font-family: 'Arial', sans-serif; background-color: #f4f4f4; margin: 0; padding: 0;}
        header {background-color: #35424a; color: #ffffff; padding-top: 30px; min-height: 70px; border-bottom: #e8491d 3px solid;}
        header a {color: #ffffff; text-decoration: none; text-transform: uppercase; font-size: 16px;}
        header ul {margin: 0; padding: 0;}
        header li {float: left; display: inline; padding: 0 20px 0 20px;}
        header #branding {float: left;}
        header #branding h1 {margin: 0;}
        header nav {float: right; margin-top: 10px;}
        #showcase {min-height: 400px; background: url('https://i.imgur.com/qZ7eY9M.jpg') no-repeat 0 -400px; text-align: center; color: #ffffff;}
        #showcase h1 {margin-top: 100px; font-size: 55px; margin-bottom: 10px;}
        #booking-form {background: #ffffff; padding: 20px; margin: 20px auto; width: 50%;}
        #booking-form h2 {text-align: center;}
        #booking-form input[type="text"], #booking-form input[type="email"], #booking-form input[type="date"], #booking-form textarea {
            width: 100%; padding: 10px; margin: 5px 0 20px 0; border: 1px solid #cccccc;
        }
        #booking-form input[type="submit"] {
            width: 100%; background-color: #e8491d; color: #ffffff; border: none; padding: 10px;
            font-size: 18px; cursor: pointer;
        }
        footer {padding: 20px; margin-top: 20px; color: #ffffff; background-color: #35424a; text-align: center;}
    </style>
</head>
<body>
    <header>
        <div id="branding">
            <h1>EliteBookings</h1>
        </div>
        <nav>
            <ul>
                <li><a href="/">Home</a></li>
                <li><a href="#">Destinations</a></li>
                <li><a href="#">Offers</a></li>
            </ul>
        </nav>
    </header>
    <section id="showcase">
        <h1>Discover Luxury</h1>
        <p>Book the world's finest hotels and resorts</p>
    </section>
    <section id="booking-form">
        <h2>Book Your Stay</h2>
        <form method="post" action="/book">
            <label for="name">Name:</label>
            <input type="text" id="name" name="name" required>
            <label for="email">Email:</label>
            <input type="email" id="email" name="email" required>
            <label for="checkin">Check-in Date:</label>
            <input type="date" id="checkin" name="checkin" required>
            <label for="checkout">Check-out Date:</label>
            <input type="date" id="checkout" name="checkout" required>
            <label for="requests">Special Requests (XML format):</label>
            <textarea id="requests" name="requests" rows="10" placeholder="<requests>\n  <request>..."></textarea>
            <input type="submit" value="Confirm Booking">
        </form>
    </section>
    <footer>
        <p>EliteBookings &copy; 2023</p>
    </footer>
</body>
</html>
"""

confirmation_page = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Booking Confirmation - EliteBookings</title>
    <style>
        body {font-family: 'Arial', sans-serif; background-color: #f4f4f4; padding: 20px;}
        #confirmation {background: #ffffff; padding: 20px; margin: auto; width: 50%;}
        #confirmation h2 {text-align: center; color: #e8491d;}
        #details {margin-top: 20px;}
        #details p {font-size: 18px;}
    </style>
</head>
<body>
    <section id="confirmation">
        <h2>Thank You {{ name }}!</h2>
        <p>Your booking from {{ checkin }} to {{ checkout }} has been confirmed.</p>
        <div id="details">
            <h3>Your Special Requests:</h3>
            <ul>
            {% for req in requests %}
                <li>{{ req }}</li>
            {% endfor %}
            </ul>
        </div>
    </section>
</body>
</html>
"""

@app.route('/', methods=['GET'])
def index():
    return render_template_string(index_page)

@app.route('/book', methods=['POST'])
def book():
    name = request.form.get('name')
    email = request.form.get('email')
    checkin = request.form.get('checkin')
    checkout = request.form.get('checkout')
    requests_xml = request.form.get('requests')

    # Parse the XML data (intentionally vulnerable to XXE)
    try:
        parser = etree.XMLParser()
        requests_tree = etree.fromstring(requests_xml.encode(), parser=parser)
        requests_list = [elem.text for elem in requests_tree.findall('.//request')]
    except Exception as e:
        requests_list = ['No valid special requests provided.']

    return render_template_string(confirmation_page, name=name, checkin=checkin, checkout=checkout, requests=requests_list)

if __name__ == '__main__':
    app.run(debug=True)