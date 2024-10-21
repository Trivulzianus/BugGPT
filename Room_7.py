from flask import Flask, request, render_template_string
import os

app = Flask(__name__)

# The narrative of the web page where participants will play the role of a detective
# decrypting a mysterious message from a secure vault, secured by a Digital Oracle.

html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>The Oracle's Enigma</title>
    <style>
        body {
            background-color: #1b1b2f;
            color: #e94560;
            font-family: 'Courier New', Courier, monospace;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .container {
            text-align: center;
            width: 80%;
            max-width: 600px;
            padding: 20px;
            border: 2px solid #162447;
            border-radius: 15px;
            background-color: #1f4068;
        }
        h1 {
            color: #e94560;
        }
        .narrative {
            color: #e1e1e1;
            margin-bottom: 20px;
        }
        .code_box {
            background-color: #0f3460;
            border: 1px solid #e94560;
            padding: 10px;
            border-radius: 8px;
        }
        textarea {
            width: 100%;
            height: 150px;
            margin-top: 20px;
            padding: 10px;
            background-color: #0f3460;
            color: #e1e1e1;
            border: 1px solid #e94560;
            border-radius: 5px;
            resize: none;
        }
        button {
            background-color: #e94560;
            color: #fff;
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            margin-top: 15px;
        }
        button:hover {
            background-color: #d33f54;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>The Oracle's Enigma</h1>
        <p class="narrative">
            As a master detective and savvy cybersecurity specialist, you've been tasked with accessing
            a digital vault safeguarded by an enigmatic Oracle. The ancient device only responds to a
            specific query format. Can you decrypt the Oracle's language?
        </p>
        <div class="code_box">
            <code>
                Oracle: "<strong>&lt;?xml version='1.0' ?&gt;</strong><br>
                &nbsp;&nbsp;&lt;!DOCTYPE note [<br>
                &nbsp;&nbsp;&lt;!ELEMENT note ANY &gt;<br>
                &nbsp;&nbsp;&lt;!ENTITY secret SYSTEM "file://{{ entity }}" &gt;<br>
                ]&gt;<br>
                &nbsp;&nbsp;&lt;note&gt;<br>
                &nbsp;&nbsp;&nbsp;&nbsp;&lt;text&gt;&amp;secret;&lt;/text&gt;<br>
                &nbsp;&nbsp;&lt;/note&gt;"
            </code>
        </div>
        <form method="POST">
            <textarea name="xml_input" placeholder="Encode your query here..."></textarea>
            <button type="submit">Submit Query</button>
        </form>
        <p class="narrative">
            Warning: The digital vault is sensitive to unintended manipulations. Handle with care!
        </p>
    </div>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def index():
    response = "Awaiting your oracle query..."
    if request.method == "POST":
        xml_input = request.form.get('xml_input')
        response = process_xml(xml_input)
    return render_template_string(html_content + """<div style='text-align: center; color:#e1e1e1;'>
                                                    <p>{}</p></div>""".format(response))

def process_xml(xml_data):
    try:
        # Vulnerable spot for XXE attack
        from xml.etree import ElementTree as ET
        tree = ET.fromstring(xml_data)
        secret = tree.find('text').text
        # Simulate retrieval of secret data
        if "SECRET_TOKEN" in secret:
            return "You've successfully retrieved the hidden token!"
    except Exception as e:
        return "Invalid Query: The Oracle has no reply."
    return "No secret found."

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)