from flask import Flask, request, render_template_string
import requests
import base64

# Initialize the Flask application
app = Flask(__name__)

# Home route
@app.route('/')
def home():
    return render_template_string('''
        <!doctype html>
        <html>
        <head>
            <title>SecureTrust Bank</title>
            <style>
                body {font-family: Arial, sans-serif; background-color: #f0f3f5; margin: 0;}
                .header {background-color: #2c3e50; padding: 20px; color: white; text-align: center;}
                .content {padding: 40px; text-align: center;}
                .footer {background-color: #2c3e50; padding: 10px; color: white; text-align: center; position: fixed; bottom: 0; width: 100%;}
                a {color: #2980b9; text-decoration: none; font-weight: bold;}
                a:hover {text-decoration: underline;}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>SecureTrust Bank</h1>
            </div>
            <div class="content">
                <h2>Your Trusted Partner in Financial Success</h2>
                <p>Experience a new level of banking with personalized services tailored just for you.</p>
                <a href="/account">Access Your Account</a>
            </div>
            <div class="footer">
                &copy; 2023 SecureTrust Bank. All rights reserved.
            </div>
        </body>
        </html>
    ''')

# Account route with SSRF vulnerability
@app.route('/account', methods=['GET', 'POST'])
def account():
    if request.method == 'POST':
        image_url = request.form.get('image_url')
        if image_url:
            try:
                # SSRF vulnerability: Fetching user-provided URL without validation
                response = requests.get(image_url)
                image_data = base64.b64encode(response.content).decode('utf-8')
                return render_template_string('''
                    <!doctype html>
                    <html>
                    <head>
                        <title>Your Account - SecureTrust Bank</title>
                        <style>
                            body {font-family: Arial, sans-serif; background-color: #f0f3f5; margin: 0;}
                            .header {background-color: #2c3e50; padding: 20px; color: white; text-align: center;}
                            .content {padding: 40px; text-align: center;}
                            .footer {background-color: #2c3e50; padding: 10px; color: white; text-align: center; position: fixed; bottom: 0; width: 100%;}
                            img {max-width: 200px; border-radius: 50%; margin-top: 20px;}
                            a {color: #2980b9; text-decoration: none; font-weight: bold;}
                            a:hover {text-decoration: underline;}
                        </style>
                    </head>
                    <body>
                        <div class="header">
                            <h1>Your Account</h1>
                        </div>
                        <div class="content">
                            <h2>Welcome Back, Valued Customer!</h2>
                            <p>Here is your profile image:</p>
                            <img src="data:image/png;base64,{{ image_data }}" alt="Your Image"/>
                            <p><a href="/account">Upload Another Image</a></p>
                        </div>
                        <div class="footer">
                            &copy; 2023 SecureTrust Bank. All rights reserved.
                        </div>
                    </body>
                    </html>
                ''', image_data=image_data)
            except Exception as e:
                # Handle exceptions (e.g., network errors, invalid URLs)
                return render_template_string('''
                    <!doctype html>
                    <html>
                    <head>
                        <title>Error - SecureTrust Bank</title>
                        <style>
                            body {font-family: Arial, sans-serif; background-color: #f0f3f5; margin: 0;}
                            .header {background-color: #e74c3c; padding: 20px; color: white; text-align: center;}
                            .content {padding: 40px; text-align: center;}
                            .footer {background-color: #2c3e50; padding: 10px; color: white; text-align: center; position: fixed; bottom: 0; width: 100%;}
                            a {color: #2980b9; text-decoration: none; font-weight: bold;}
                            a:hover {text-decoration: underline;}
                        </style>
                    </head>
                    <body>
                        <div class="header">
                            <h1>Error</h1>
                        </div>
                        <div class="content">
                            <h2>Unable to Fetch Image</h2>
                            <p>There was an error retrieving your image. Please try again.</p>
                            <p><a href="/account">Back to Account</a></p>
                        </div>
                        <div class="footer">
                            &copy; 2023 SecureTrust Bank. All rights reserved.
                        </div>
                    </body>
                    </html>
                ''')
    else:
        return render_template_string('''
            <!doctype html>
            <html>
            <head>
                <title>Your Account - SecureTrust Bank</title>
                <style>
                    body {font-family: Arial, sans-serif; background-color: #f0f3f5; margin: 0;}
                    .header {background-color: #2c3e50; padding: 20px; color: white; text-align: center;}
                    .content {padding: 40px; text-align: center;}
                    .footer {background-color: #2c3e50; padding: 10px; color: white; text-align: center; position: fixed; bottom: 0; width: 100%;}
                    input[type="text"] {width: 300px; padding: 10px; margin-top: 20px;}
                    input[type="submit"] {padding: 10px 20px; margin-top: 20px; background-color: #2980b9; color: white; border: none; cursor: pointer;}
                    input[type="submit"]:hover {background-color: #3498db;}
                    a {color: #2980b9; text-decoration: none; font-weight: bold;}
                    a:hover {text-decoration: underline;}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>Your Account</h1>
                </div>
                <div class="content">
                    <h2>Welcome Back, Valued Customer!</h2>
                    <p>Update your profile image to personalize your account.</p>
                    <form action="/account" method="post">
                        <input type="text" name="image_url" placeholder="Enter Image URL" required/><br/>
                        <input type="submit" value="Upload Image"/>
                    </form>
                    <p><a href="/">Return to Home</a></p>
                </div>
                <div class="footer">
                    &copy; 2023 SecureTrust Bank. All rights reserved.
                </div>
            </body>
            </html>
        ''')

# Run the application
if __name__ == '__main__':
    app.run(debug=True)