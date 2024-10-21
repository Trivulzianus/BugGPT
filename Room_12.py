from flask import Flask, request, render_template_string, jsonify
import xml.etree.ElementTree as ET

app = Flask(__name__)

# Homepage HTML with a narrative and complex design
html_page = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>The Enchanted Library</title>
    <style>
        body {
            background-color: #2E4053;
            color: #EAECEE;
            font-family: 'Trebuchet MS', sans-serif;
        }
        #header {
            text-align: center;
            margin-top: 50px;
            color: #F7DC6F;
        }
        #section {
            padding: 20px;
        }
        #formContainer {
            background-color: #D5D8DC;
            padding: 15px;
            border-radius: 10px;
            max-width: 500px;
            margin: 30px auto;
            color: #1C2833;
        }
        #submitButton {
            background-color: #3498DB;
            padding: 10px;
            border: none;
            border-radius: 5px;
            color: white;
            cursor: pointer;
        }
        #hintSection {
            display: none;
            margin-top: 20px;
        }
        h3 {
            color: #A569BD;
        }
    </style>
</head>
<body>
    <div id="header">
        <h1>Welcome to The Enchanted Library</h1>
        <p>Explore the mystical corridors and unveil its secrets. Submit the correct scroll to unlock the archive.</p>
    </div>
    <div id="section">
        <div id="formContainer">
            <h3>Submit Your Enchanted Scroll</h3>
            <form method="POST" action="/">
                <textarea name="scroll" rows="10" cols="50"></textarea><br>
                <button type="submit" id="submitButton">Submit</button>
            </form>
        </div>
    </div>
</body>
</html>
"""

# Vulnerable route to test XXE
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        scroll_data = request.form.get('scroll')
        try:
            # Parse the XML input
            tree = ET.ElementTree(ET.fromstring(scroll_data))
            root = tree.getroot()
            response_data = {child.tag: child.text for child in root}

            return jsonify(response_data)
        except ET.ParseError:
            return 'Invalid XML format!', 400

    return render_template_string(html_page)

if __name__ == '__main__':
    app.run(debug=True)