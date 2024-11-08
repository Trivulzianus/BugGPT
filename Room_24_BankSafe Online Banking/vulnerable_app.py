from flask import Flask, render_template_string, request
from lxml import etree

app = Flask(__name__)

home_page = '''
<!DOCTYPE html>
<html>
<head>
    <title>BankSafe Online Banking</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f2f2f2;
            margin: 0;
        }
        .header {
            background-color: #004080;
            color: white;
            padding: 20px 0;
            text-align: center;
            margin-bottom: 40px;
        }
        .content {
            margin: 0 auto;
            width: 60%;
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0px 0px 10px #aaa;
        }
        .content h2 {
            color: #004080;
            margin-top: 0;
        }
        .footer {
            background-color: #004080;
            color: white;
            position: fixed;
            bottom: 0;
            width: 100%;
            height: 40px;
            text-align: center;
            padding-top: 10px;
        }
        .upload-form {
            margin-top: 30px;
        }
        .upload-form input[type="file"] {
            padding: 5px;
            font-size: 16px;
        }
        .upload-form input[type="submit"] {
            background-color: #004080;
            color: white;
            border: none;
            padding: 10px 30px;
            font-size: 16px;
            cursor: pointer;
            margin-left: 10px;
        }
        .upload-form input[type="submit"]:hover {
            background-color: #003366;
        }
        .result {
            background-color: #e6f2ff;
            padding: 20px;
            border: 1px solid #004080;
            border-radius: 5px;
            margin-top: 30px;
            overflow-x: auto;
        }
        .result h3 {
            margin-top: 0;
            color: #004080;
        }
        pre {
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        p {
            font-size: 16px;
            line-height: 1.5em;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>BankSafe Online Banking</h1>
    </div>
    <div class="content">
        <h2>Welcome to BankSafe</h2>
        <p>
            At BankSafe, your security is our priority. Manage your accounts, transfer funds, and more with our secure online banking portal.
        </p>
        <h3>Upload Your Statement</h3>
        <p>
            Upload your account statement in XML format to view your latest transactions online.
        </p>
        <form class="upload-form" action="/" method="post" enctype="multipart/form-data">
            <input type="file" name="file" accept=".xml" required>
            <input type="submit" value="Upload">
        </form>
        {% if result %}
        <div class="result">
            <h3>Account Statement:</h3>
            <pre>{{ result }}</pre>
        </div>
        {% endif %}
    </div>
    <div class="footer">
        &copy; 2023 BankSafe. All rights reserved.
    </div>
</body>
</html>
'''

@app.route('/', methods=['GET', 'POST'])
def home():
    result = None
    if request.method == 'POST':
        xml_file = request.files['file']
        xml_data = xml_file.read()
        try:
            # Vulnerable XML parser (XXE vulnerability)
            parser = etree.XMLParser()
            tree = etree.fromstring(xml_data, parser)
            result = etree.tostring(tree, pretty_print=True).decode()
        except Exception as e:
            result = f"Error parsing XML: {e}"
    return render_template_string(home_page, result=result)

if __name__ == '__main__':
    app.run(debug=True)