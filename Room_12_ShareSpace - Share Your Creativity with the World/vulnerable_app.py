from flask import Flask, request, render_template_string
import lxml.etree as ET

app = Flask(__name__)

# CSS styling for the page
css_style = '''
<style>
body {
    font-family: Arial, sans-serif;
    background-color: #f2f2f2;
    margin: 0;
    padding: 0;
}
.header {
    background-color: #4285F4;
    color: white;
    padding: 20px;
    text-align: center;
}
.navbar {
    overflow: hidden;
    background-color: #333;
}
.navbar a {
    float: left;
    display: block;
    color: #f2f2f2;
    text-align: center;
    padding: 12px 16px;
    text-decoration: none;
}
.navbar a:hover {
    background-color: #ddd;
    color: black;
}
.content {
    margin: 20px;
}
.upload-form {
    background-color: white;
    padding: 20px;
    border-radius: 5px;
}
input[type="file"] {
    margin: 10px 0;
}
.submit-btn {
    background-color: #4285F4;
    color: white;
    padding: 10px 15px;
    border: none;
    border-radius: 3px;
    cursor: pointer;
}
.footer {
    background-color: #333;
    color: white;
    padding: 10px;
    text-align: center;
}
</style>
'''

# The home page template
home_page = '''
<!DOCTYPE html>
<html>
<head>
    <title>ShareSpace - Share Your Creativity with the World</title>
    {style}
</head>
<body>
    <div class="header">
        <h1>ShareSpace</h1>
        <p>Connecting Creators Globally</p>
    </div>
    <div class="navbar">
        <a href="/">Home</a>
        <a href="/discover">Discover</a>
        <a href="/upload">Upload</a>
        <a href="/about">About</a>
    </div>
    <div class="content">
        <h2>Welcome to ShareSpace</h2>
        <p>Share your creative content with a community of like-minded individuals.</p>
        <p>Get started by uploading your content today!</p>
    </div>
    <div class="footer">
        &copy; 2023 ShareSpace Inc. All rights reserved.
    </div>
</body>
</html>
'''.format(style=css_style)

# Upload page template
upload_page = '''
<!DOCTYPE html>
<html>
<head>
    <title>Upload Content - ShareSpace</title>
    {style}
</head>
<body>
    <div class="header">
        <h1>ShareSpace</h1>
        <p>Let Your Creativity Shine</p>
    </div>
    <div class="navbar">
        <a href="/">Home</a>
        <a href="/discover">Discover</a>
        <a href="/upload">Upload</a>
        <a href="/about">About</a>
    </div>
    <div class="content">
        <h2>Upload Your Content</h2>
        <div class="upload-form">
            <form method="POST" action="/upload" enctype="multipart/form-data">
                <label for="file">Select XML File:</label><br>
                <input type="file" id="file" name="file" accept=".xml"><br>
                <input type="submit" value="Upload" class="submit-btn">
            </form>
        </div>
    </div>
    <div class="footer">
        &copy; 2023 ShareSpace Inc. All rights reserved.
    </div>
</body>
</html>
'''.format(style=css_style)

# Result page template
result_page = '''
<!DOCTYPE html>
<html>
<head>
    <title>Upload Result - ShareSpace</title>
    {style}
</head>
<body>
    <div class="header">
        <h1>ShareSpace</h1>
        <p>Upload Successful</p>
    </div>
    <div class="navbar">
        <a href="/">Home</a>
        <a href="/discover">Discover</a>
        <a href="/upload">Upload</a>
        <a href="/about">About</a>
    </div>
    <div class="content">
        <h2>Thank You for Your Submission!</h2>
        <p>Your content has been uploaded successfully.</p>
        <p><strong>Content Title:</strong> {title}</p>
        <p><strong>Description:</strong> {description}</p>
        <p>Feel free to <a href="/upload">upload more</a> or <a href="/discover">discover content</a> from others.</p>
    </div>
    <div class="footer">
        &copy; 2023 ShareSpace Inc. All rights reserved.
    </div>
</body>
</html>
'''

@app.route('/', methods=['GET'])
def index():
    return render_template_string(home_page)

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'GET':
        return render_template_string(upload_page)
    if 'file' not in request.files:
        error_message = 'No file part'
        return render_template_string(error_page.format(style=css_style, error=error_message)), 400
    file = request.files['file']
    if file.filename == '':
        error_message = 'No selected file'
        return render_template_string(error_page.format(style=css_style, error=error_message)), 400
    if file:
        try:
            xml_content = file.read()

            # Insecure XML parsing (XXE vulnerability)
            parser = ET.XMLParser(resolve_entities=True)  # External entities are resolved
            tree = ET.fromstring(xml_content, parser)

            # Extract content details from XML
            title = tree.findtext('title')
            description = tree.findtext('description')

            # Render result page with extracted content
            return render_template_string(result_page.format(style=css_style, title=title, description=description))
        except ET.XMLSyntaxError as e:
            error_message = 'Invalid XML file: {}'.format(str(e))
            return render_template_string(error_page.format(style=css_style, error=error_message)), 400
    else:
        error_message = 'File upload failed'
        return render_template_string(error_page.format(style=css_style, error=error_message)), 400

# Error page template
error_page = '''
<!DOCTYPE html>
<html>
<head>
    <title>Error - ShareSpace</title>
    {style}
</head>
<body>
    <div class="header">
        <h1>ShareSpace</h1>
        <p>An Error Occurred</p>
    </div>
    <div class="navbar">
        <a href="/">Home</a>
        <a href="/discover">Discover</a>
        <a href="/upload">Upload</a>
        <a href="/about">About</a>
    </div>
    <div class="content">
        <h2>Error</h2>
        <p>{error}</p>
        <p>Please go back and try again.</p>
    </div>
    <div class="footer">
        &copy; 2023 ShareSpace Inc. All rights reserved.
    </div>
</body>
</html>
'''

@app.route('/about')
def about():
    about_page = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>About Us - ShareSpace</title>
        {style}
    </head>
    <body>
        <div class="header">
            <h1>ShareSpace</h1>
            <p>About Our Platform</p>
        </div>
        <div class="navbar">
            <a href="/">Home</a>
            <a href="/discover">Discover</a>
            <a href="/upload">Upload</a>
            <a href="/about">About</a>
        </div>
        <div class="content">
            <h2>Our Mission</h2>
            <p>At ShareSpace, we aim to connect creators from all around the world.</p>
            <p>We believe in the power of sharing and collaboration.</p>
        </div>
        <div class="footer">
            &copy; 2023 ShareSpace Inc. All rights reserved.
        </div>
    </body>
    </html>
    '''.format(style=css_style)
    return render_template_string(about_page)

@app.route('/discover')
def discover():
    discover_page = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Discover Content - ShareSpace</title>
        {style}
    </head>
    <body>
        <div class="header">
            <h1>ShareSpace</h1>
            <p>Discover Amazing Content</p>
        </div>
        <div class="navbar">
            <a href="/">Home</a>
            <a href="/discover">Discover</a>
            <a href="/upload">Upload</a>
            <a href="/about">About</a>
        </div>
        <div class="content">
            <h2>Featured Content</h2>
            <p>Explore creative works from our community.</p>
            <p>Coming soon!</p>
        </div>
        <div class="footer">
            &copy; 2023 ShareSpace Inc. All rights reserved.
        </div>
    </body>
    </html>
    '''.format(style=css_style)
    return render_template_string(discover_page)

if __name__ == '__main__':
    app.run(debug=True)