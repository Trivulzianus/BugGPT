from flask import Flask, request, render_template_string
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# HTML content with a narrative and colorful design
html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>The Enigma of Elemental Orders</title>
    <style>
        body {
            background: linear-gradient(135deg, #f06, #4a90e2);
            color: #fff;
            font-family: 'Courier New', Courier, monospace;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            text-align: center;
        }
        .container {
            background: rgba(0, 0, 0, 0.7);
            padding: 20px;
            border-radius: 15px;
            box-shadow: 0 0 10px rgba(0,0,0,0.5);
        }
        h1 {
            font-size: 2.5em;
        }
        p {
            font-size: 1.2em;
            margin-bottom: 20px;
        }
        input[type='text'] {
            width: 80%;
            padding: 10px;
            margin-bottom: 20px;
            border: none;
            border-radius: 5px;
        }
        input[type='submit'] {
            background: #f06;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            color: #fff;
            font-size: 1em;
            cursor: pointer;
        }
        input[type='submit']:hover {
            background: #e8358b;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>The Enigma of Elemental Orders</h1>
        <p>Brave seeker, to unlock the secrets of the ancients, you must communicate in the language of the elements. Only through the ancient dialect of XML can the forgotten lore be unveiled. Proceed with caution as the forces that guard this knowledge are perilous.</p>
        <form method="post" action="/quest">
            <input type="text" name="xml_input" placeholder="Enter the Elemental Text" autocomplete="off"/>
            <br>
            <input type="submit" value="Submit"/>
        </form>
    </div>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(html_content)

@app.route('/quest', methods=['POST'])
def quest():
    xml_input = request.form['xml_input']
    # Intentional XXE vulnerability to process XML input
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml_input)
        return f"<h2>Secrets Revealed:</h2><pre>{ET.tostring(root, encoding='unicode')}</pre>"
    except ET.ParseError as e:
        return f"<h2>Failed to unlock the secrets!</h2><p>Error: {str(e)}</p>"

if __name__ == '__main__':
    app.run(debug=True)