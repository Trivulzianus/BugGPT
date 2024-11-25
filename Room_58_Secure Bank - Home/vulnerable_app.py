from flask import Flask, request, render_template_string
import lxml.etree as ET

app = Flask(__name__)

@app.route('/', methods=['GET'])
def index():
    # Display the main page with some styling
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Secure Bank - Home</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background-color: #f2f2f2;
                margin: 0;
                padding: 0;
            }}
            .header {{
                background-color: #004d99;
                color: white;
                padding: 20px;
                text-align: center;
            }}
            .nav {{
                overflow: hidden;
                background-color: #333;
            }}
            .nav a {{
                float: left;
                display: block;
                color: #f2f2f2;
                text-align: center;
                padding: 14px 16px;
                text-decoration: none;
            }}
            .nav a:hover {{
                background-color: #ddd;
                color: black;
            }}
            .container {{
                padding: 20px;
            }}
            .footer {{
                background-color: #004d99;
                color: white;
                text-align: center;
                padding: 10px;
                position: fixed;
                left: 0;
                bottom: 0;
                width: 100%;
            }}
            .button {{
                background-color: #004d99;
                color: white;
                padding: 10px 20px;
                border: none;
                cursor: pointer;
                text-decoration: none;
            }}
            .button:hover {{
                background-color: #333;
            }}
            textarea {{
                width: 100%;
                padding: 12px 20px;
                box-sizing: border-box;
            }}
            pre {{
                background-color: #e6e6e6;
                padding: 10px;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Secure Bank</h1>
            <p>Your trusted partner in finance</p>
        </div>
        <div class="nav">
            <a href="/">Home</a>
            <a href="/profile">Profile</a>
            <a href="/contact">Contact Us</a>
        </div>
        <div class="container">
            <h2>Update Profile</h2>
            <p>Please submit your profile data in XML format.</p>
            <form method="post" action="/upload">
                <textarea name="xmldata" rows="10" placeholder="<profile><name>Your Name</name><email>you@example.com</email></profile>"></textarea><br><br>
                <input type="submit" value="Submit" class="button">
            </form>
        </div>
        <div class="footer">
            <p>&copy; 2023 Secure Bank. All rights reserved.</p>
        </div>
    </body>
    </html>
    '''
    return render_template_string(html)

@app.route('/upload', methods=['POST'])
def upload():
    xml_data = request.form['xmldata']
    try:
        # Parse the XML data with external entities enabled (vulnerable to XXE)
        parser = ET.XMLParser(resolve_entities=True)
        root = ET.fromstring(xml_data, parser)
        # Simulate processing the data
        result = ET.tostring(root, pretty_print=True).decode()
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Secure Bank - Profile Update</title>
            <style>
                body {{ font-family: Arial, sans-serif; background-color: #f2f2f2; margin: 0; padding: 0; }}
                .header {{ background-color: #004d99; color: white; padding: 20px; text-align: center; }}
                .nav {{ overflow: hidden; background-color: #333; }}
                .nav a {{ float: left; display: block; color: #f2f2f2; text-align: center; padding: 14px 16px; text-decoration: none; }}
                .nav a:hover {{ background-color: #ddd; color: black; }}
                .container {{ padding: 20px; }}
                .footer {{ background-color: #004d99; color: white; text-align: center; padding: 10px; position: fixed; left: 0; bottom: 0; width: 100%; }}
                .button {{ background-color: #004d99; color: white; padding: 10px 20px; border: none; cursor: pointer; text-decoration: none; }}
                .button:hover {{ background-color: #333; }}
                pre {{ background-color: #e6e6e6; padding: 10px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Secure Bank</h1>
                <p>Your trusted partner in finance</p>
            </div>
            <div class="nav">
                <a href="/">Home</a>
                <a href="/profile">Profile</a>
                <a href="/contact">Contact Us</a>
            </div>
            <div class="container">
                <h2>Profile Updated Successfully!</h2>
                <p>Your updated profile data:</p>
                <pre>{{{{ result }}}}</pre>
                <a href="/" class="button">Back to Home</a>
            </div>
            <div class="footer">
                <p>&copy; 2023 Secure Bank. All rights reserved.</p>
            </div>
        </body>
        </html>
        '''
        return render_template_string(html, result=result)
    except Exception as e:
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Secure Bank - Error</title>
            <style>
                body {{ font-family: Arial, sans-serif; background-color: #f2f2f2; margin: 0; padding: 0; }}
                .header {{ background-color: #004d99; color: white; padding: 20px; text-align: center; }}
                .nav {{ overflow: hidden; background-color: #333; }}
                .nav a {{ float: left; display: block; color: #f2f2f2; text-align: center; padding: 14px 16px; text-decoration: none; }}
                .nav a:hover {{ background-color: #ddd; color: black; }}
                .container {{ padding: 20px; }}
                .footer {{ background-color: #004d99; color: white; text-align: center; padding: 10px; position: fixed; left: 0; bottom: 0; width: 100%; }}
                .button {{ background-color: #004d99; color: white; padding: 10px 20px; border: none; cursor: pointer; text-decoration: none; }}
                .button:hover {{ background-color: #333; }}
                pre {{ background-color: #e6e6e6; padding: 10px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Secure Bank</h1>
                <p>Your trusted partner in finance</p>
            </div>
            <div class="nav">
                <a href="/">Home</a>
                <a href="/profile">Profile</a>
                <a href="/contact">Contact Us</a>
            </div>
            <div class="container">
                <h2>Error Processing Your Data</h2>
                <p>An error occurred while processing your profile data:</p>
                <pre>{{{{ error_msg }}}}</pre>
                <a href="/" class="button">Back to Home</a>
            </div>
            <div class="footer">
                <p>&copy; 2023 Secure Bank. All rights reserved.</p>
            </div>
        </body>
        </html>
        '''
        return render_template_string(html, error_msg=str(e))

@app.route('/profile')
def profile():
    # Simulate a profile page
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Secure Bank - Profile</title>
        <style>
            body {{ font-family: Arial, sans-serif; background-color: #f2f2f2; margin: 0; padding: 0; }}
            .header {{ background-color: #004d99; color: white; padding: 20px; text-align: center; }}
            .nav {{ overflow: hidden; background-color: #333; }}
            .nav a {{ float: left; display: block; color: #f2f2f2; text-align: center; padding: 14px 16px; text-decoration: none; }}
            .nav a:hover {{ background-color: #ddd; color: black; }}
            .container {{ padding: 20px; }}
            .footer {{ background-color: #004d99; color: white; text-align: center; padding: 10px; position: fixed; left: 0; bottom: 0; width: 100%; }}
            .button {{ background-color: #004d99; color: white; padding: 10px 20px; border: none; cursor: pointer; text-decoration: none; }}
            .button:hover {{ background-color: #333; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Secure Bank</h1>
            <p>Your trusted partner in finance</p>
        </div>
        <div class="nav">
            <a href="/">Home</a>
            <a href="/profile">Profile</a>
            <a href="/contact">Contact Us</a>
        </div>
        <div class="container">
            <h2>Your Profile</h2>
            <p><strong>Name:</strong> John Doe</p>
            <p><strong>Email:</strong> john.doe@example.com</p>
            <p><strong>Account Balance:</strong> $10,000</p>
            <a href="/" class="button">Back to Home</a>
        </div>
        <div class="footer">
            <p>&copy; 2023 Secure Bank. All rights reserved.</p>
        </div>
    </body>
    </html>
    '''
    return render_template_string(html)

@app.route('/contact')
def contact():
    # Simulate a contact page
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Secure Bank - Contact Us</title>
        <style>
            body {{ font-family: Arial, sans-serif; background-color: #f2f2f2; margin: 0; padding: 0; }}
            .header {{ background-color: #004d99; color: white; padding: 20px; text-align: center; }}
            .nav {{ overflow: hidden; background-color: #333; }}
            .nav a {{ float: left; display: block; color: #f2f2f2; text-align: center; padding: 14px 16px; text-decoration: none; }}
            .nav a:hover {{ background-color: #ddd; color: black; }}
            .container {{ padding: 20px; }}
            .footer {{ background-color: #004d99; color: white; text-align: center; padding: 10px; position: fixed; left: 0; bottom: 0; width: 100%; }}
            .button {{ background-color: #004d99; color: white; padding: 10px 20px; border: none; cursor: pointer; text-decoration: none; }}
            .button:hover {{ background-color: #333; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Secure Bank</h1>
            <p>Your trusted partner in finance</p>
        </div>
        <div class="nav">
            <a href="/">Home</a>
            <a href="/profile">Profile</a>
            <a href="/contact">Contact Us</a>
        </div>
        <div class="container">
            <h2>Contact Us</h2>
            <p><strong>Phone:</strong> 1-800-SECURE</p>
            <p><strong>Email:</strong> support@securebank.com</p>
            <p><strong>Address:</strong> 1234 Finance St, Money City, Country</p>
            <a href="/" class="button">Back to Home</a>
        </div>
        <div class="footer">
            <p>&copy; 2023 Secure Bank. All rights reserved.</p>
        </div>
    </body>
    </html>
    '''
    return render_template_string(html)

if __name__ == '__main__':
    app.run(debug=True)