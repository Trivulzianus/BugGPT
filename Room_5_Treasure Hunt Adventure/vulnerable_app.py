from flask import Flask, request, render_template_string
import os

app = Flask(__name__)

# Load the XML payload
def parse_xml(xml_data):
    try:
        # This is where the vulnerability is introduced, by allowing external entities
        from lxml import etree
        parser = etree.XMLParser(resolve_entities=True)
        tree = etree.fromstring(xml_data, parser=parser)
        return tree.findtext('clue')
    except Exception as e:
        return str(e)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'GET':
        # Return a colorful, adventure-themed main page
        return render_template_string('''
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Treasure Hunt Adventure</title>
                <style>
                    body {
                        background: linear-gradient(120deg, #89f7fe 0%, #66a6ff 100%);
                        font-family: 'Arial', sans-serif;
                        color: #333;
                        text-align: center;
                        padding: 50px;
                    }
                    .container {
                        background-color: white;
                        padding: 20px;
                        border-radius: 8px;
                        box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                        max-width: 600px;
                        margin: auto;
                    }
                    h1 {
                        font-size: 2em;
                        color: #ff6347;
                    }
                    form {
                        margin: 30px 0;
                    }
                    input[type=file] {
                        padding: 10px;
                        margin: 10px 0;
                    }
                    input[type=submit] {
                        background-color: #ff6347;
                        color: white;
                        padding: 10px 20px;
                        border: none;
                        border-radius: 5px;
                        cursor: pointer;
                    }
                    input[type=submit]:hover {
                        background-color: #e5533d;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Welcome to the Treasure Hunt Adventure!</h1>
                    <p>Your journey begins with an ancient parchment, decoded through the arcane arts of XML. Upload your scroll to proceed.</p>
                    <form action="/" method="post" enctype="multipart/form-data">
                        <input type="file" name="file" accept=".xml"><br>
                        <input type="submit" value="Decode Clue">
                    </form>
                </div>
            </body>
            </html>
        ''')

    if request.method == 'POST':
        # Handle the XML file upload and parsing
        uploaded_file = request.files['file']
        if uploaded_file:
            file_content = uploaded_file.read()
            clue = parse_xml(file_content)
            return render_template_string('''
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Decoded Clue</title>
                    <style>
                        body {
                            background-color: #ffeead;
                            font-family: 'Arial', sans-serif;
                            text-align: center;
                            padding: 50px;
                        }
                        .result {
                            background-color: white;
                            padding: 20px;
                            border-radius: 8px;
                            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                            max-width: 600px;
                            margin: auto;
                        }
                        h2 {
                            font-size: 1.5em;
                            color: #3c763d;
                        }
                        a {
                            color: #007bb5;
                            text-decoration: none;
                        }
                        a:hover {
                            text-decoration: underline;
                        }
                    </style>
                </head>
                <body>
                    <div class="result">
                        <h2>Your Decoded Clue:</h2>
                        <p>{{ clue }}</p>
                        <a href="/">Try Again</a>
                    </div>
                </body>
                </html>''', clue=clue)

    return 'Method not allowed', 405

if __name__ == '__main__':
    app.run(debug=True)