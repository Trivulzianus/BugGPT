from flask import Flask, render_template_string, request
import lxml.etree as ET

app = Flask(__name__)

# Home page template
home_page = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Global Bank - Secure Online Banking</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0;}
        #header {background-color: #003366; color: #ffffff; padding: 20px;}
        #content {padding: 40px;}
        #footer {background-color: #003366; color: #ffffff; text-align: center; padding: 10px; position: fixed; bottom: 0; width: 100%;}
        .button {background-color: #007acc; color: white; padding: 15px 25px; text-align: center; display: inline-block; border: none; border-radius: 5px; text-decoration: none; font-size: 16px;}
        .button:hover {background-color: #005f99;}
    </style>
</head>
<body>
    <div id="header">
        <h1>Global Bank</h1>
        <p>Your Trusted Partner in Finance</p>
    </div>
    <div id="content">
        <h2>Welcome to Global Bank's Online Portal</h2>
        <p>Experience secure and seamless banking services anywhere, anytime.</p>
        <a href="/upload" class="button">Upload Financial Statement</a>
    </div>
    <div id="footer">
        &copy; 2023 Global Bank. All rights reserved.
    </div>
</body>
</html>
"""

# Upload page template
upload_page = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Upload Financial Statement - Global Bank</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0;}
        #header {background-color: #003366; color: #ffffff; padding: 20px;}
        #content {padding: 40px;}
        #footer {background-color: #003366; color: #ffffff; text-align: center; padding: 10px; position: fixed; bottom: 0; width: 100%;}
        .input-file {padding: 10px; background-color: #fff; border-radius: 5px; border: 1px solid #ccc; width: 100%;}
        .submit-button {background-color: #007acc; color: white; padding: 15px 25px; border: none; border-radius: 5px; font-size: 16px;}
        .submit-button:hover {background-color: #005f99;}
    </style>
</head>
<body>
    <div id="header">
        <h1>Global Bank</h1>
        <p>Your Trusted Partner in Finance</p>
    </div>
    <div id="content">
        <h2>Upload Your Financial Statement</h2>
        <p>Please upload your financial statement in XML format for processing.</p>
        <form action="/upload" method="post" enctype="multipart/form-data">
            <input type="file" name="file" accept=".xml" class="input-file"><br><br>
            <input type="submit" value="Upload" class="submit-button">
        </form>
    </div>
    <div id="footer">
        &copy; 2023 Global Bank. All rights reserved.
    </div>
</body>
</html>
"""

# Result page template
result_page = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Processed Statement - Global Bank</title>
    <style>
        body {font-family: Courier New, monospace; background-color: #f4f4f4; margin: 0;}
        #header {background-color: #003366; color: #ffffff; padding: 20px;}
        #content {padding: 40px;}
        #footer {background-color: #003366; color: #ffffff; text-align: center; padding: 10px; position: fixed; bottom: 0; width: 100%;}
        pre {background-color: #ffffff; padding: 20px; border-radius: 5px; border: 1px solid #ccc; overflow: auto;}
    </style>
</head>
<body>
    <div id="header">
        <h1>Global Bank</h1>
        <p>Your Trusted Partner in Finance</p>
    </div>
    <div id="content">
        <h2>Your Processed Financial Statement</h2>
        <pre>{{ result }}</pre>
    </div>
    <div id="footer">
        &copy; 2023 Global Bank. All rights reserved.
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(home_page)

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        file = request.files.get('file')
        if file and file.filename.endswith('.xml'):
            xml_content = file.read()
            try:
                # Vulnerable XML parsing (XXE vulnerability)
                parser = ET.XMLParser()
                tree = ET.fromstring(xml_content, parser)
                result = ET.tostring(tree, pretty_print=True).decode()
                return render_template_string(result_page, result=result)
            except ET.XMLSyntaxError as e:
                error_message = f"An error occurred while processing your XML file: {e}"
                return render_template_string(upload_page + f"<p style='color:red;'>{error_message}</p>")
        else:
            error_message = "Please upload a valid XML file."
            return render_template_string(upload_page + f"<p style='color:red;'>{error_message}</p>")
    else:
        return render_template_string(upload_page)

if __name__ == '__main__':
    app.run(debug=True)