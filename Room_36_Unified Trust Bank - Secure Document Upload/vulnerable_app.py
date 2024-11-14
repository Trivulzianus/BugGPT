from flask import Flask, render_template_string, request
import xml.etree.ElementTree as ET

# Initialize the Flask application
app = Flask(__name__)

# Define the homepage route
@app.route('/', methods=['GET', 'POST'])
def index():
    # HTML template for the web page
    html_content = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Unified Trust Bank - Secure Document Upload</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background-color: #f4f8fb;
                margin: 0;
                padding: 0;
            }
            .header {
                background-color: #003366;
                color: #ffffff;
                padding: 20px;
                text-align: center;
            }
            .container {
                padding: 50px;
            }
            .form-group {
                margin-bottom: 15px;
            }
            label {
                display: block;
                font-weight: bold;
                margin-bottom: 5px;
            }
            textarea {
                width: 100%;
                height: 200px;
                padding: 10px;
                border: 1px solid #ccc;
                border-radius: 4px;
                resize: none;
            }
            input[type="submit"] {
                background-color: #003366;
                color: #ffffff;
                padding: 10px 20px;
                border: none;
                border-radius: 4px;
                cursor: pointer;
            }
            .result {
                margin-top: 20px;
                padding: 10px;
                background-color: #e7f3fe;
                border: 1px solid #b3d7ff;
                border-radius: 4px;
            }
            .footer {
                background-color: #f1f1f1;
                color: #888888;
                text-align: center;
                padding: 10px;
                position: fixed;
                left: 0;
                bottom: 0;
                width: 100%;
            }
            .logo {
                width: 200px;
            }
        </style>
    </head>
    <body>
        <div class="header">
            <img src="https://via.placeholder.com/200x50.png?text=Unified+Trust+Bank" alt="Unified Trust Bank" class="logo">
        </div>
        <div class="container">
            <h2>Secure Document Upload Portal</h2>
            <p>Welcome to the Unified Trust Bank's secure document upload portal. Please submit your financial documents in XML format using the form below.</p>
            <form method="post">
                <div class="form-group">
                    <label for="xml">XML Document:</label>
                    <textarea name="xml" id="xml" required></textarea>
                </div>
                <input type="submit" value="Upload Document">
            </form>
            {% if result %}
            <div class="result">
                {{ result }}
            </div>
            {% endif %}
        </div>
        <div class="footer">
            &copy; 2023 Unified Trust Bank. All rights reserved.
        </div>
    </body>
    </html>
    '''
    result = ''
    if request.method == 'POST':
        # Retrieve the XML data from the form
        xml_data = request.form['xml']
        try:
            # Parse the XML data (This is where the XXE vulnerability exists)
            root = ET.fromstring(xml_data)
            # Process the XML data (For demonstration purposes, we're not doing anything additional)
            result = 'Your document has been uploaded and processed successfully.'
        except Exception as e:
            result = 'An error occurred while processing your document: ' + str(e)
    # Render the HTML template with the result
    return render_template_string(html_content, result=result)

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)