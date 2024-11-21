from flask import Flask, request, render_template_string
from lxml import etree

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    output = ''
    if request.method == 'POST':
        xml_input = request.form['xml']
        try:
            parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
            root = etree.fromstring(xml_input.encode(), parser)
            output = etree.tostring(root, pretty_print=True).decode()
        except Exception as e:
            output = f'Error parsing XML: {e}'

    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>MyBank International - Secure Transactions</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f0f8ff; margin: 0; padding: 0; }
        .header { background-color: #2e8b57; color: white; padding: 20px; text-align: center; }
        .nav { background-color: #3cb371; overflow: hidden; }
        .nav a { float: left; display: block; color: white; text-align: center; padding: 14px 16px; text-decoration: none; }
        .nav a:hover { background-color: #ddd; color: black; }
        .container { padding: 20px; }
        h2 { color: #2e8b57; }
        textarea { width: 100%; height: 200px; }
        input[type=submit] { background-color: #2e8b57; color: white; padding: 10px 20px; border: none; cursor: pointer; margin-top: 10px; }
        input[type=submit]:hover { background-color: #3cb371; }
        .output { background-color: #e6e6fa; padding: 10px; margin-top: 20px; white-space: pre-wrap; }
        .footer { background-color: #2e8b57; color: white; text-align: center; padding: 10px; position: fixed; width: 100%; bottom: 0; }
        .info-box { background-color: #fffacd; padding: 10px; margin-top: 20px; border-left: 6px solid #ffeb3b; }
        a { color: #2e8b57; text-decoration: none; }
    </style>
</head>
<body>
    <div class="header">
        <h1>MyBank International</h1>
        <p>Your Trusted Partner in Global Finance</p>
    </div>
    <div class="nav">
        <a href="#">Home</a>
        <a href="#">Accounts</a>
        <a href="#">Transfer Funds</a>
        <a href="#">Investments</a>
        <a href="#">Support</a>
    </div>
    <div class="container">
        <h2>International Funds Transfer</h2>
        <p>Welcome to MyBank International's secure funds transfer portal. Please submit your transaction details in XML format below. Our advanced processing system ensures secure and efficient handling of your funds.</p>
        <div class="info-box">
            <strong>Important:</strong> Ensure that your XML follows the standard format as per our <a href="#">XML Schema Guidelines</a>. Incorrect formatting may lead to processing delays.
        </div>
        <form method="post">
            <textarea name="xml">{{ request.form.get('xml', '') }}</textarea><br>
            <input type="submit" value="Process Transaction">
        </form>
        {% if output %}
        <h2>Transaction Processing Result:</h2>
        <div class="output">{{ output }}</div>
        {% endif %}
    </div>
    <div class="footer">
        &copy; 2023 MyBank International. All rights reserved.
    </div>
</body>
</html>
''', output=output)

if __name__ == '__main__':
    app.run(debug=True)