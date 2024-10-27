from flask import Flask, request, render_template_string
import xml.etree.ElementTree as ET

app = Flask(__name__)

home_page = '''
<!DOCTYPE html>
<html>
<head>
    <title>SkyHigh Airlines - Flight Booking</title>
    <style>
        body { font-family: Arial, sans-serif; background: #e0f7fa; }
        .container { width: 500px; margin: 0 auto; padding-top: 50px; }
        h1 { text-align: center; color: #00695c; }
        form { background: #ffffff; padding: 20px; border-radius: 5px; }
        input[type="text"], input[type="date"] {
            width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ccc; border-radius: 3px;
        }
        input[type="submit"] {
            background: #00695c; color: #ffffff; border: none; padding: 10px; border-radius: 3px; cursor: pointer;
            width: 100%;
        }
        input[type="submit"]:hover { background: #004d40; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Book Your Flight</h1>
        <form action="/book" method="post">
            <label>Full Name:</label>
            <input type="text" name="name" required />
            <label>Destination:</label>
            <input type="text" name="destination" required />
            <label>Departure Date:</label>
            <input type="date" name="date" required />
            <input type="submit" value="Book Now" />
        </form>
    </div>
</body>
</html>
'''

confirmation_page = '''
<!DOCTYPE html>
<html>
<head>
    <title>SkyHigh Airlines - Confirmation</title>
</head>
<body>
    <h1>Booking Confirmation</h1>
    <p>Thank you, {{ name }}! Your flight to {{ destination }} on {{ date }} has been booked.</p>
</body>
</html>
'''

error_page = '''
<!DOCTYPE html>
<html>
<head>
    <title>SkyHigh Airlines - Error</title>
</head>
<body>
    <h1>Error Processing Your Booking</h1>
    <p>{{ error_message }}</p>
</body>
</html>
'''

@app.route('/')
def index():
    return home_page

@app.route('/book', methods=['POST'])
def book():
    name = request.form['name']
    destination = request.form['destination']
    date = request.form['date']
    
    # Construct XML data (vulnerable to XXE)
    xml_data = f'''<?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE booking [
    <!ELEMENT booking ANY >
    <!ENTITY xxe SYSTEM "file:///etc/passwd" >
    ]>
    <booking>
        <name>{name}</name>
        <destination>{destination}</destination>
        <date>{date}</date>
    </booking>
    '''
    
    try:
        # Parse XML data without disabling external entities
        tree = ET.fromstring(xml_data)
        # Extract data (simulating use of parsed XML)
        parsed_name = tree.find('name').text
        parsed_destination = tree.find('destination').text
        parsed_date = tree.find('date').text
        
        return render_template_string(confirmation_page, name=parsed_name, destination=parsed_destination, date=parsed_date)
    except ET.ParseError as e:
        return render_template_string(error_page, error_message=str(e))

if __name__ == '__main__':
    app.run(debug=True)