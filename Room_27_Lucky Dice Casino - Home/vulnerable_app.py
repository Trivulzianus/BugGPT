from flask import Flask, request, render_template_string
from lxml import etree

app = Flask(__name__)

main_page = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Lucky Dice Casino - Home</title>
    <style>
        body {
            background-color: #2b2b2b;
            font-family: 'Arial', sans-serif;
            color: #fff;
            margin: 0;
            padding: 0;
        }
        .header {
            background-color: #1a1a1a;
            padding: 20px;
            text-align: center;
        }
        .header h1 {
            color: #ffcc00;
            margin: 0;
        }
        .nav {
            background-color: #333;
            overflow: hidden;
        }
        .nav a {
            float: left;
            display: block;
            color: #ffcc00;
            text-align: center;
            padding: 14px 16px;
            text-decoration: none;
        }
        .nav a:hover {
            background-color: #575757;
            color: white;
        }
        .content {
            padding: 40px;
            text-align: center;
        }
        .content h2 {
            color: #ffcc00;
        }
        .form-container {
            background-color: #333;
            display: inline-block;
            padding: 20px;
            border-radius: 10px;
        }
        .form-container textarea {
            width: 300px;
            height: 150px;
        }
        .form-container input[type=submit] {
            margin-top: 10px;
            padding: 10px 20px;
            background-color: #ffcc00;
            border: none;
            color: #000;
            font-weight: bold;
            cursor: pointer;
            border-radius: 5px;
        }
        .footer {
            background-color: #1a1a1a;
            padding: 10px;
            text-align: center;
            color: #ffcc00;
            position: fixed;
            width: 100%;
            bottom: 0;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Lucky Dice Casino</h1>
    </div>
    <div class="nav">
        <a href="/">Home</a>
        <a href="#">Games</a>
        <a href="#">Promotions</a>
        <a href="#">VIP Club</a>
        <a href="#">Contact Us</a>
    </div>
    <div class="content">
        <h2>Create Your Player Profile</h2>
        <p>Upload your profile in XML format to receive personalized offers!</p>
        <div class="form-container">
            <form method="post">
                <textarea name="profile" placeholder="Enter your profile XML here..."></textarea><br>
                <input type="submit" value="Upload Profile">
            </form>
        </div>
    </div>
    <div class="footer">
        &copy; 2023 Lucky Dice Casino. All rights reserved.
    </div>
</body>
</html>
"""

profile_page = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Lucky Dice Casino - Player Profile</title>
    <style>
        body {
            background-color: #2b2b2b;
            font-family: 'Arial', sans-serif;
            color: #fff;
            margin: 0;
            padding: 0;
        }
        .header {
            background-color: #1a1a1a;
            padding: 20px;
            text-align: center;
        }
        .header h1 {
            color: #ffcc00;
            margin: 0;
        }
        .profile {
            padding: 40px;
            text-align: center;
        }
        .profile h2 {
            color: #ffcc00;
        }
        .profile p {
            font-size: 18px;
        }
        .offers {
            margin-top: 30px;
        }
        .offers h3 {
            color: #ffcc00;
        }
        .offers ul {
            list-style-type: none;
            padding: 0;
        }
        .offers li {
            background-color: #333;
            margin: 5px 0;
            padding: 10px;
            border-radius: 5px;
        }
        .footer {
            background-color: #1a1a1a;
            padding: 10px;
            text-align: center;
            color: #ffcc00;
            position: fixed;
            width: 100%;
            bottom: 0;
        }
        .nav {
            background-color: #333;
            overflow: hidden;
        }
        .nav a {
            float: left;
            display: block;
            color: #ffcc00;
            text-align: center;
            padding: 14px 16px;
            text-decoration: none;
        }
        .nav a:hover {
            background-color: #575757;
            color: white;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Lucky Dice Casino</h1>
    </div>
    <div class="nav">
        <a href="/">Home</a>
        <a href="#">Games</a>
        <a href="#">Promotions</a>
        <a href="#">VIP Club</a>
        <a href="#">Contact Us</a>
    </div>
    <div class="profile">
        <h2>Welcome, {{ username }}!</h2>
        <p>{{ bio }}</p>
        <div class="offers">
            <h3>Exclusive Offers for You:</h3>
            <ul>
                <li>100% Bonus on your next deposit!</li>
                <li>Free spins on the Mega Reel!</li>
                <li>Access to VIP tournaments!</li>
            </ul>
        </div>
    </div>
    <div class="footer">
        &copy; 2023 Lucky Dice Casino. All rights reserved.
    </div>
</body>
</html>
"""

error_page = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Lucky Dice Casino - Error</title>
    <style>
        body {
            background-color: #2b2b2b;
            font-family: 'Arial', sans-serif;
            color: #fff;
            margin: 0;
            padding: 0;
        }
        .header {
            background-color: #1a1a1a;
            padding: 20px;
            text-align: center;
        }
        .header h1 {
            color: #ff0000;
            margin: 0;
        }
        .error {
            padding: 40px;
            text-align: center;
        }
        .error h2 {
            color: #ff0000;
        }
        .error p {
            font-size: 18px;
        }
        .back-link a {
            color: #ffcc00;
            text-decoration: none;
            font-weight: bold;
        }
        .footer {
            background-color: #1a1a1a;
            padding: 10px;
            text-align: center;
            color: #ffcc00;
            position: fixed;
            width: 100%;
            bottom: 0;
        }
        .nav {
            background-color: #333;
            overflow: hidden;
        }
        .nav a {
            float: left;
            display: block;
            color: #ffcc00;
            text-align: center;
            padding: 14px 16px;
            text-decoration: none;
        }
        .nav a:hover {
            background-color: #575757;
            color: white;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Error</h1>
    </div>
    <div class="nav">
        <a href="/">Home</a>
        <a href="#">Games</a>
        <a href="#">Promotions</a>
        <a href="#">VIP Club</a>
        <a href="#">Contact Us</a>
    </div>
    <div class="error">
        <h2>Oops! Something went wrong.</h2>
        <p>{{ error_message }}</p>
        <div class="back-link">
            <p><a href="/">Go back to the main page</a></p>
        </div>
    </div>
    <div class="footer">
        &copy; 2023 Lucky Dice Casino. All rights reserved.
    </div>
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Get XML data from form
        xml_data = request.form['profile']
        # Parse XML data using lxml (vulnerable to XXE)
        try:
            # This is where the XXE vulnerability is introduced
            parser = etree.XMLParser(resolve_entities=True)
            doc = etree.fromstring(xml_data, parser)
            # Extract user details from the XML
            username = doc.findtext('username')
            bio = doc.findtext('bio')
            # Display user profile page
            return render_template_string(profile_page, username=username, bio=bio)
        except Exception as e:
            return render_template_string(error_page, error_message=str(e))
    else:
        # Render the main page with form
        return render_template_string(main_page)

if __name__ == '__main__':
    app.run(debug=True)