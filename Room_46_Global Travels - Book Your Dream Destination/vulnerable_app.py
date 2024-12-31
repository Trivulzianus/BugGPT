from flask import Flask, request, render_template_string
import xml.etree.ElementTree as ET

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def booking():
    if request.method == 'POST':
        booking_info = request.form.get('booking_info')
        try:
            root = ET.fromstring(booking_info)
            customer_name = root.find('name').text
            destination = root.find('destination').text
            date = root.find('date').text

            confirmation_message = f"""
            <h2>Booking Confirmation</h2>
            <p>Thank you, {customer_name}, for booking your trip to {destination} on {date}.</p>
            """
            return render_template_string(confirmation_message)
        except Exception as e:
            error_message = f"""
            <h2>Error</h2>
            <p>There was an error processing your booking details.</p>
            """
            return render_template_string(error_message)
    else:
        booking_form = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Global Travels - Book Your Dream Destination</title>
            <style>
                body {font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0;}
                .header {background-color: #2196F3; color: #fff; padding: 20px; text-align: center;}
                .container {padding: 20px;}
                .booking-form {background-color: #fff; padding: 20px; border-radius: 5px;}
                input[type=text], textarea {width: 100%; padding: 10px; margin-top: 10px; border: 1px solid #ccc; border-radius: 4px;}
                input[type=submit] {background-color: #2196F3; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer;}
                input[type=submit]:hover {background-color: #0b7dda;}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Global Travels</h1>
                <p>Your Gateway to the World's Best Destinations</p>
            </div>
            <div class="container">
                <div class="booking-form">
                    <h2>Book Your Trip Now</h2>
                    <form method="POST">
                        <label for="booking_info">Enter Your Booking Details (in XML format):</label>
                        <textarea id="booking_info" name="booking_info" rows="10" placeholder="<booking>\n  <name>Your Name</name>\n  <destination>Your Destination</destination>\n  <date>YYYY-MM-DD</date>\n</booking>"></textarea>
                        <input type="submit" value="Submit Booking">
                    </form>
                </div>
            </div>
        </body>
        </html>
        '''
        return render_template_string(booking_form)

if __name__ == '__main__':
    app.run(debug=True)