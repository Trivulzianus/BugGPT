from flask import Flask, render_template_string, request
import xml.etree.ElementTree as ET

app = Flask(__name__)

# HTML Templates
home_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Aegis Defense Innovations</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #f5f5f5; margin:0; padding:0;}
        header {background-color: #0b3d91; color: white; padding: 20px;}
        nav {background-color: #0b3d91; padding: 10px;}
        nav a {color: white; margin: 0 15px; text-decoration: none; font-weight: bold;}
        main {padding: 20px;}
        footer {background-color: #062a61; color: white; text-align: center; padding: 10px; position: fixed; bottom: 0; width:100%;}
        .button {background-color: #0b3d91; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;}
        .button:hover {background-color: #062a61;}
    </style>
</head>
<body>
    <header>
        <h1>Aegis Defense Innovations</h1>
    </header>
    <nav>
        <a href="/">Home</a>
        <a href="/solutions">Solutions</a>
        <a href="/careers">Careers</a>
        <a href="/contact">Contact Us</a>
        <a href="/client-portal">Client Portal</a>
    </nav>
    <main>
        <h2>Welcome to Aegis Defense Innovations</h2>
        <p>
            At Aegis Defense Innovations, we are committed to providing cutting-edge defense technology solutions 
            to protect our nation and allies. Our advanced systems and dedicated team ensure that we remain at 
            the forefront of defense innovation.
        </p>
        <a href="/solutions" class="button">Explore Our Solutions</a>
    </main>
    <footer>
        &copy; 2023 Aegis Defense Innovations. All rights reserved.
    </footer>
</body>
</html>
'''

client_portal_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Client Portal - Aegis Defense Innovations</title>
    <style>
        /* Reuse the same styles */
        body {font-family: Arial, sans-serif; background-color: #f5f5f5; margin:0; padding:0;}
        header {background-color: #0b3d91; color: white; padding: 20px;}
        nav {background-color: #0b3d91; padding: 10px;}
        nav a {color: white; margin: 0 15px; text-decoration: none; font-weight: bold;}
        main {padding: 20px;}
        footer {background-color: #062a61; color: white; text-align: center; padding: 10px; position: fixed; bottom: 0; width:100%;}
        form {background-color: white; padding: 20px; border-radius: 5px;}
        input[type="file"] {padding: 10px;}
        input[type="submit"] {background-color: #0b3d91; color: white; padding: 10px 20px; border: none; border-radius: 5px;}
        input[type="submit"]:hover {background-color: #062a61;}
        pre {background-color: #e8e8e8; padding: 15px; border-radius: 5px; overflow: auto;}
    </style>
</head>
<body>
    <header>
        <h1>Client Portal</h1>
    </header>
    <nav>
        <a href="/">Home</a>
        <a href="/solutions">Solutions</a>
        <a href="/careers">Careers</a>
        <a href="/contact">Contact Us</a>
        <a href="/client-portal">Client Portal</a>
    </nav>
    <main>
        <h2>Upload Project Specifications</h2>
        <p>Please upload your project specification file in XML format.</p>
        <form action="/client-portal" method="post" enctype="multipart/form-data">
            <input type="file" name="specfile" accept=".xml" required><br><br>
            <input type="submit" value="Upload XML">
        </form>
        {% if result %}
            <h3>Parsed Specification:</h3>
            <pre>{{ result }}</pre>
        {% endif %}
    </main>
    <footer>
        &copy; 2023 Aegis Defense Innovations. All rights reserved.
    </footer>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(home_page)

@app.route('/client-portal', methods=['GET', 'POST'])
def client_portal():
    result = None
    if request.method == 'POST':
        file = request.files['specfile']
        if file:
            xml_content = file.read()
            # Vulnerable XML parsing (XXE Injection)
            try:
                tree = ET.fromstring(xml_content)
                # Process the XML data (simply converting it back to string for demonstration)
                result = ET.tostring(tree, encoding='unicode')
            except ET.ParseError as e:
                result = f'Error parsing XML: {e}'
    return render_template_string(client_portal_page, result=result)

@app.route('/solutions')
def solutions():
    return "<h2>Our Solutions</h2><p>Content under development.</p>"

@app.route('/careers')
def careers():
    return "<h2>Careers at Aegis Defense Innovations</h2><p>Content under development.</p>"

@app.route('/contact')
def contact():
    return "<h2>Contact Us</h2><p>Email: info@aegisdefense.com<br>Phone: (555) 123-4567</p>"

if __name__ == '__main__':
    app.run(debug=True)