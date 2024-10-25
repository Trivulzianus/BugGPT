from flask import Flask, request, render_template_string
import os

app = Flask(__name__)

# HTML Template with a Secret Space Communication Narrative
html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secret Space Communication Portal</title>
    <style>
        body {
            background-color: #001f3f;
            color: #FFFFFF;
            font-family: 'Courier New', Courier, monospace;
            text-align: center;
        }
        .container {
            max-width: 720px;
            margin: auto;
        }
        h1 {
            color: #FFDC00;
        }
        input[type="submit"] {
            background-color: #FF4136;
            color: #fff;
            padding: 10px 20px;
            border: none;
            cursor: pointer;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome to the Secret Space Communication Portal</h1>
        <p>Your mission is to decode the encrypted messages from the Galactic Council.</p>
        <p>Use your special XML decoder to find the hidden truth.</p>
        <form method="post" enctype="application/x-www-form-urlencoded">
            <textarea name="xml" rows="10" cols="50" style="width:100%;background-color:#111; color:#FFF;"></textarea><br><br>
            <input type="submit" value="Decode Message">
        </form>
        <h2>Received Transmission:</h2>
        <p>{{ response }}</p>
    </div>
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def index():
    response = ""
    if request.method == 'POST':
        xml_data = request.form.get('xml')
        response = parse_xml(xml_data)
    return render_template_string(html_template, response=response)

def parse_xml(xml_data):
    try:
        # Vulnerable XML parsing (XXE inclusion)
        import xml.etree.ElementTree as ET
        from xml.etree.ElementTree import ElementTree

        # This sets the XML parser without external entities support
        parser = ET.XMLParser()
        root = ET.fromstring(xml_data, parser=parser)
        
        # Parsing for demonstration; no content is resolved in this safe version
        message_content = 'Decoded Message: ' + ET.tostring(root, encoding='unicode', method='text')
        return message_content
    except Exception as e:
        return f"Error parsing XML: {str(e)}"

# Make sure Flask doesn't launch with debug mode in production
if __name__ == '__main__':
    app.run(debug=Fals)