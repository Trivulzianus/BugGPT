from flask import Flask, request, render_template_string
from lxml import etree

app = Flask(__name__)

# Home page HTML template
home_page_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Global Trust Bank - Secure Online Banking</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #f4f4f4; margin:0; padding:0;}
        .header {background-color: #004080; color: #ffffff; padding: 20px;}
        .header h1 {margin:0;}
        .nav {overflow: hidden; background-color: #333;}
        .nav a {float: left; display: block; color: #f2f2f2; text-align: center;
                padding: 14px 16px; text-decoration: none;}
        .nav a:hover {background-color: #ddd; color: black;}
        .container {padding: 20px;}
        .footer {background-color: #004080; color: #ffffff; text-align: center;
                 padding: 10px; position: fixed; left: 0; bottom: 0; width: 100%;}
        .form-group {margin-bottom: 15px;}
        label {display: block; margin-bottom: 5px;}
        input[type="file"] {padding: 5px;}
        input[type="submit"] {background-color: #004080; color: #ffffff; padding: 10px 20px;
                             border: none; cursor: pointer;}
        input[type="submit"]:hover {background-color: #003366;}
    </style>
</head>
<body>
    <div class="header">
        <h1>Global Trust Bank</h1>
    </div>
    <div class="nav">
        <a href="/">Home</a>
        <a href="/accounts">Accounts</a>
        <a href="/loans">Loans</a>
        <a href="/contact">Contact Us</a>
    </div>
    <div class="container">
        <h2>Upload Your Account Details</h2>
        <p>Please upload your account XML file to view your latest account information.</p>
        <form action="/process" method="post" enctype="multipart/form-data">
            <div class="form-group">
                <label for="xmlfile">Account XML File:</label>
                <input type="file" name="xmlfile" id="xmlfile" accept=".xml" required>
            </div>
            <input type="submit" value="Upload and View">
        </form>
    </div>
    <div class="footer">
        &copy; 2023 Global Trust Bank. All rights reserved.
    </div>
</body>
</html>
"""

# Result page HTML template
result_page_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Your Account Information - Global Trust Bank</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #f4f4f4; margin:0; padding:0;}
        .header {background-color: #004080; color: #ffffff; padding: 20px;}
        .header h1 {margin:0;}
        .nav {overflow: hidden; background-color: #333;}
        .nav a {float: left; display: block; color: #f2f2f2; text-align: center;
                padding: 14px 16px; text-decoration: none;}
        .nav a:hover {background-color: #ddd; color: black;}
        .container {padding: 20px;}
        .footer {background-color: #004080; color: #ffffff; text-align: center;
                 padding: 10px; position: fixed; left: 0; bottom: 0; width: 100%;}
        table {width: 50%; margin: auto; border-collapse: collapse;}
        td, th {border: 1px solid #ddd; padding: 8px;}
        th {background-color: #f2f2f2;}
    </style>
</head>
<body>
    <div class="header">
        <h1>Global Trust Bank</h1>
    </div>
    <div class="nav">
        <a href="/">Home</a>
        <a href="/accounts">Accounts</a>
        <a href="/loans">Loans</a>
        <a href="/contact">Contact Us</a>
    </div>
    <div class="container">
        <h2>Your Account Information</h2>
        <table>
            <tr>
                <th>Account Number</th>
                <td>{{ account_number }}</td>
            </tr>
            <tr>
                <th>Balance</th>
                <td>${{ balance }}</td>
            </tr>
        </table>
    </div>
    <div class="footer">
        &copy; 2023 Global Trust Bank. All rights reserved.
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(home_page_html)

@app.route('/process', methods=['POST'])
def process():
    if 'xmlfile' not in request.files:
        return "No file part", 400
    file = request.files['xmlfile']
    if file.filename == '':
        return "No selected file", 400
    try:
        xml_data = file.read()
        parser = etree.XMLParser(resolve_entities=True)
        tree = etree.fromstring(xml_data, parser)
        # Vulnerable XML parsing without disabling external entities
        account_number = tree.findtext('account')
        balance = tree.findtext('balance')
        return render_template_string(result_page_html, account_number=account_number, balance=balance)
    except Exception as e:
        return f"An error occurred: {str(e)}", 400

if __name__ == '__main__':
    app.run(debug=True)