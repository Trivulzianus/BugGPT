from flask import Flask, render_template_string, request
import xml.etree.ElementTree as ET

app = Flask(__name__)

# HTML template for the main page
main_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SecureTech Defense Systems</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; }
        .header { background-color: #002f6c; color: white; padding: 20px; text-align: center; }
        .nav { overflow: hidden; background-color: #333; }
        .nav a { float: left; display: block; color: #f2f2f2; text-align: center; padding: 14px 16px; text-decoration: none; }
        .nav a:hover { background-color: #ddd; color: black; }
        .content { padding: 20px; }
        .upload-form { background-color: white; padding: 20px; border-radius: 5px; max-width: 500px; margin: auto; }
        .footer { background-color: #002f6c; color: white; padding: 10px; text-align: center; position: fixed; width: 100%; bottom: 0; }
        input[type="file"] { margin-bottom: 10px; width: 100%; }
        input[type="submit"] { background-color: #002f6c; color: white; padding: 10px 20px; border: none; cursor: pointer; }
        input[type="submit"]:hover { background-color: #014a9e; }
        h2 { text-align: center; }
        p { text-align: center; }
    </style>
</head>
<body>
    <div class="header">
        <h1>SecureTech Defense Systems</h1>
        <p>Innovating Tomorrow's Defense Technologies Today</p>
    </div>
    <div class="nav">
        <a href="/">Home</a>
        <a href="/about">About Us</a>
        <a href="/careers">Careers</a>
        <a href="/contact">Contact</a>
    </div>
    <div class="content">
        <div class="upload-form">
            <h2>Submit Your System Configuration</h2>
            <p>Please upload your XML configuration file for validation.</p>
            <form action="/upload" method="post" enctype="multipart/form-data">
                <input type="file" name="xml_file" accept=".xml" required><br>
                <input type="submit" value="Upload">
            </form>
        </div>
    </div>
    <div class="footer">
        &copy; 2023 SecureTech Defense Systems. All rights reserved.
    </div>
</body>
</html>
'''

# HTML template for the result page
result_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Configuration Results</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; }
        .header { background-color: #002f6c; color: white; padding: 20px; text-align: center; }
        .nav { overflow: hidden; background-color: #333; }
        .nav a { float: left; display: block; color: #f2f2f2; text-align: center; padding: 14px 16px; text-decoration: none; }
        .nav a:hover { background-color: #ddd; color: black; }
        .content { padding: 20px; }
        .footer { background-color: #002f6c; color: white; padding: 10px; text-align: center; position: fixed; width: 100%; bottom: 0; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 50px; }
        table, th, td { border: 1px solid #ddd; }
        th, td { padding: 12px; text-align: left; }
        tr:nth-child(even){background-color: #f2f2f2}
        h2 { text-align: center; }
    </style>
</head>
<body>
    <div class="header">
        <h1>SecureTech Defense Systems</h1>
        <p>Configuration Analysis Results</p>
    </div>
    <div class="nav">
        <a href="/">Home</a>
        <a href="/about">About Us</a>
        <a href="/careers">Careers</a>
        <a href="/contact">Contact</a>
    </div>
    <div class="content">
        <h2>System Configuration Details</h2>
        <table>
            <tr>
                <th>Parameter</th>
                <th>Value</th>
            </tr>
            {% for param, value in params.items() %}
            <tr>
                <td>{{ param }}</td>
                <td>{{ value }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
    <div class="footer">
        &copy; 2023 SecureTech Defense Systems. All rights reserved.
    </div>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(main_page)

@app.route('/upload', methods=['POST'])
def upload():
    if 'xml_file' not in request.files:
        return 'No file part', 400

    file = request.files['xml_file']
    if file.filename == '':
        return 'No selected file', 400

    if file:
        # Parse the uploaded XML file (This is where the XXE vulnerability exists)
        try:
            tree = ET.parse(file)  # Vulnerable to XXE
            root = tree.getroot()

            params = {}
            for child in root:
                params[child.tag] = child.text

            return render_template_string(result_page, params=params)
        except ET.ParseError:
            return 'Invalid XML file', 400

    return 'File upload failed', 400

@app.route('/about')
def about():
    return '<h2>About SecureTech Defense Systems</h2><p>SecureTech Defense Systems is a global leader in cutting-edge defense technologies...</p>'

@app.route('/careers')
def careers():
    return '<h2>Careers at SecureTech</h2><p>Join our team of experts and be part of the future of defense technology...</p>'

@app.route('/contact')
def contact():
    return '<h2>Contact Us</h2><p>Email: info@securetechdefense.com<br>Phone: +1 (555) 123-4567</p>'

if __name__ == '__main__':
    app.run(debug=True)