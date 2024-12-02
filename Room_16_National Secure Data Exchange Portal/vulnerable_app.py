from flask import Flask, request, render_template_string
from lxml import etree

app = Flask(__name__)

home_page = '''
<!DOCTYPE html>
<html>
<head>
    <title>National Secure Data Exchange Portal</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f4; }
        .header { background-color: #283E4A; padding: 20px; text-align: center; }
        .header h1 { color: #FFFFFF; }
        .nav { overflow: hidden; background-color: #333; }
        .nav a { float: left; display: block; color: #f2f2f2; text-align: center;
                 padding: 14px 16px; text-decoration: none; }
        .nav a:hover { background-color: #ddd; color: black; }
        .container { padding: 20px; }
        .footer { background-color: #283E4A; padding: 10px; text-align: center;
                  color: #FFFFFF; position: fixed; left: 0; bottom: 0; width: 100%; }
        input[type="file"] { padding: 5px; }
        input[type="submit"] { background-color: #283E4A; color: white; padding: 10px 20px;
                              border: none; cursor: pointer; }
        input[type="submit"]:hover { background-color: #4CAF50; }
        table { width: 50%; margin: auto; border-collapse: collapse; }
        table, th, td { border: 1px solid #ddd; padding: 8px; }
        th { background-color: #283E4A; color: white; }
    </style>
</head>
<body>
    <div class="header">
        <h1>National Secure Data Exchange Portal</h1>
    </div>
    <div class="nav">
        <a href="/">Home</a>
        <a href="#">Services</a>
        <a href="#">Contact Us</a>
        <a href="#">Help</a>
    </div>
    <div class="container">
        <h2>Upload Secure XML Data</h2>
        <p>Welcome to the official National Secure Data Exchange Portal. Please upload your encrypted XML file for secure processing.</p>
        <form action="/upload" method="post" enctype="multipart/form-data">
            <label for="xmlfile">Select XML file:</label>
            <input type="file" id="xmlfile" name="xmlfile" accept=".xml" required>
            <br><br>
            <input type="submit" value="Upload and Process">
        </form>
    </div>
    <div class="footer">
        &copy; 2023 National Secure Data Exchange Portal. All rights reserved.
    </div>
</body>
</html>
'''

@app.route('/', methods=['GET'])
def index():
    return home_page

@app.route('/upload', methods=['POST'])
def upload():
    xmlfile = request.files.get('xmlfile')
    if not xmlfile:
        return "No file selected.", 400
    xml_content = xmlfile.read()
    try:
        parser = etree.XMLParser()
        tree = etree.fromstring(xml_content, parser)
        data_entries = []
        for element in tree:
            data_entries.append((element.tag, element.text))
        table_rows = ''.join(f"<tr><td>{tag}</td><td>{text}</td></tr>" for tag, text in data_entries)
        response = f'''
        <html>
        <head>
            <title>Processing Results</title>
            <style>
                body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; }}
                .container {{ padding: 20px; }}
                table {{ width: 50%; margin: auto; border-collapse: collapse; }}
                table, th, td {{ border: 1px solid #ddd; padding: 8px; }}
                th {{ background-color: #283E4A; color: white; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h2>Processing Results</h2>
                <table>
                    <tr><th>Field</th><th>Value</th></tr>
                    {table_rows}
                </table>
            </div>
        </body>
        </html>
        '''
        return response
    except Exception as e:
        return f"An error occurred while processing the XML file: {str(e)}", 500

if __name__ == '__main__':
    app.run(debug=True)