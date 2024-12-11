from flask import Flask, request, render_template_string
import lxml.etree as ET

app = Flask(__name__)

# HTML template for the homepage
homepage_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ShareSphere - Your Content Hub</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; }
        .header { background-color: #4CAF50; color: white; padding: 20px; text-align: center; }
        .container { padding: 20px; }
        .upload-form { background-color: white; padding: 20px; border-radius: 5px; }
        .footer { background-color: #ddd; color: #333; text-align: center; padding: 10px; position: fixed; bottom: 0; width: 100%; }
        input[type=file] { margin: 10px 0; }
        input[type=submit] { background-color: #4CAF50; color: white; padding: 10px 15px; border: none; cursor: pointer; }
        input[type=submit]:hover { background-color: #45a049; }
    </style>
</head>
<body>
    <div class="header">
        <h1>ShareSphere</h1>
        <p>Connect. Share. Discover.</p>
    </div>
    <div class="container">
        <div class="upload-form">
            <h2>Upload Your Content</h2>
            <form action="/upload" method="post" enctype="multipart/form-data">
                <label for="xmlfile">Select XML File:</label><br>
                <input type="file" id="xmlfile" name="xmlfile" accept=".xml" required><br><br>
                <input type="submit" value="Upload and Share">
            </form>
        </div>
    </div>
    <div class="footer">
        &copy; 2023 ShareSphere Inc.
    </div>
</body>
</html>
"""

# Route for the homepage
@app.route('/')
def home():
    return render_template_string(homepage_html)

# Route to handle file uploads
@app.route('/upload', methods=['POST'])
def upload():
    if 'xmlfile' not in request.files:
        return "No file part", 400
    file = request.files['xmlfile']
    if file.filename == '':
        return "No selected file", 400
    try:
        # Parse the XML file (vulnerable to XXE)
        parser = ET.XMLParser(resolve_entities=True)
        tree = ET.parse(file, parser)
        root = tree.getroot()
        # Process the XML data (placeholder for actual content handling)
        content = ET.tostring(root, pretty_print=True).decode()
        return render_template_string("""
            <h2>File Uploaded Successfully!</h2>
            <pre>{{ content }}</pre>
            <a href="/">Back to Home</a>
        """, content=content)
    except ET.XMLSyntaxError as e:
        return f"XML Syntax Error: {e}", 400

if __name__ == '__main__':
    app.run(debug=True)