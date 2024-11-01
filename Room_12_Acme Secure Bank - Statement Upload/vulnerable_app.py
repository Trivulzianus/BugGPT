from flask import Flask, request, render_template_string
import lxml.etree as ET

app = Flask(__name__)

home_page = '''
<!DOCTYPE html>
<html>
<head>
    <title>Acme Secure Bank - Statement Upload</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f2f2f2;
        }
        #container {
            width: 50%;
            margin: auto;
            background-color: white;
            padding: 20px;
            margin-top: 50px;
            box-shadow: 0px 0px 10px 0px #888;
        }
        h1 {
            color: #333;
        }
        p {
            color: #555;
        }
        textarea {
            width: 100%;
            height: 200px;
            margin-bottom: 10px;
        }
        input[type=submit] {
            background-color: #007BFF;
            color: white;
            padding: 10px 20px;
            border: none;
            cursor: pointer;
        }
        pre {
            background-color: #eee;
            padding: 10px;
            overflow-x: auto;
        }
        footer {
            text-align: center;
            margin-top: 50px;
            color: #aaa;
        }
    </style>
</head>
<body>
    <div id="container">
        <h1>Welcome to Acme Secure Bank</h1>
        <p>At Acme Secure Bank, we value your security. Our online banking platform allows you to upload your account statements in XML format for quick processing.</p>
        <form method="post">
            <label for="xml">Paste your XML statement below:</label><br>
            <textarea name="xml" id="xml">{{ xml_content }}</textarea><br>
            <input type="submit" value="Submit">
        </form>
        {% if result %}
        <h2>Processed Statement:</h2>
        <pre>{{ result }}</pre>
        {% endif %}
    </div>
    <footer>
        &copy; 2023 Acme Secure Bank. All rights reserved.
    </footer>
</body>
</html>
'''

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        xml = request.form.get('xml')
        result = ''
        if xml:
            try:
                parser = ET.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
                doc = ET.fromstring(xml.encode('utf-8'), parser)
                result = ET.tostring(doc, pretty_print=True).decode()
            except ET.XMLSyntaxError as e:
                result = f"XML Syntax Error: {str(e)}"
            except Exception as e:
                result = f"Error: {str(e)}"
        else:
            result = "No XML provided."
        return render_template_string(home_page, xml_content=xml, result=result)
    else:
        return render_template_string(home_page, xml_content='', result='')

if __name__ == '__main__':
    app.run(debug=True)