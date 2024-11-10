from flask import Flask, render_template_string, request
from lxml import etree

app = Flask(__name__)

home_page = """
<!DOCTYPE html>
<html>
<head>
    <title>Global Trust Bank - Welcome</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f0f2f5; margin: 0; padding: 0; }
        .header { background-color: #004080; color: white; padding: 20px; text-align: center;}
        .nav { overflow: hidden; background-color: #333; }
        .nav a { float: left; display: block; color: #f2f2f2; text-align: center;
                 padding: 14px 16px; text-decoration: none; }
        .nav a:hover { background-color: #ddd; color: black; }
        .container { padding: 50px; text-align: center; }
        .button { background-color: #004080; color: white; padding: 15px 32px;
                  text-align: center; font-size: 16px; margin: 4px 2px;
                  border: none; cursor: pointer; }
        .footer { background-color: #333; color: white; padding: 10px; text-align: center; position: fixed; bottom: 0; width: 100%;}
        textarea { width: 100%; height: 200px; padding: 12px 20px; box-sizing: border-box;
                   border: 2px solid #ccc; border-radius: 4px; background-color: #f8f8f8;
                   font-size: 16px; resize: none; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Global Trust Bank</h1>
        <p>Empowering Your Financial Future</p>
    </div>
    <div class="nav">
        <a href="#">Home</a>
        <a href="#">Personal</a>
        <a href="#">Business</a>
        <a href="#">About Us</a>
        <a href="#">Contact</a>
    </div>
    <div class="container">
        <h2>Apply for a New Account</h2>
        <p>Please fill out the form below to apply for a new account. Provide your details in XML format.</p>
        <form action="/process" method="post">
            <textarea name="xml_data" placeholder="<application><name>John Doe</name></application>"></textarea><br><br>
            <input type="submit" class="button" value="Submit Application">
        </form>
    </div>
    <div class="footer">
        &copy; 2023 Global Trust Bank. All rights reserved.
    </div>
</body>
</html>
"""

result_page = """
<!DOCTYPE html>
<html>
<head>
    <title>Global Trust Bank - Application Status</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f0f2f5; margin: 0; padding: 0;}
        .header { background-color: #004080; color: white; padding: 20px; text-align: center;}
        .container { padding: 50px; text-align: center; }
        .footer { background-color: #333; color: white; padding: 10px; text-align: center; position: fixed; bottom: 0; width: 100%;}
        .success { color: green; }
        .error { color: red; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Global Trust Bank</h1>
        <p>Empowering Your Financial Future</p>
    </div>
    <div class="container">
        <h2>Application Status</h2>
        <p class="{{ status }}">{{ message }}</p>
    </div>
    <div class="footer">
        &copy; 2023 Global Trust Bank. All rights reserved.
    </div>
</body>
</html>
"""

@app.route('/', methods=['GET'])
def index():
    return render_template_string(home_page)

@app.route('/process', methods=['POST'])
def process():
    xml_data = request.form['xml_data']
    try:
        # Vulnerable XML parsing (XXE)
        doc = etree.fromstring(xml_data)
        applicant_name = doc.findtext('name')
        message = f"Thank you, {applicant_name}. Your application has been received."
        status = "success"
    except Exception as e:
        message = "An error occurred while processing your application."
        status = "error"
    return render_template_string(result_page, message=message, status=status)

if __name__ == '__main__':
    app.run(debug=Fals)