from flask import Flask, render_template_string, request, redirect, url_for

app = Flask(__name__)

# Sample HTML template for the home page
home_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Global Bank Online Services</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f4; }
        .container { width: 50%; margin: auto; overflow: hidden; }
        header { background: #50b3a2; color: #ffffff; padding-top: 30px; min-height: 70px; border-bottom: #ffffff 3px solid; }
        header a { color: #ffffff; text-decoration: none; text-transform: uppercase; font-size: 16px; }
        header ul { margin: 0; padding: 0; }
        header li { float: left; display: inline; padding: 0 20px 0 20px; }
        header #branding { float: left; }
        header #branding h1 { margin: 0; }
        header nav { float: right; margin-top: 10px; }
        #showcase { min-height: 400px; background: url('https://example.com/banner.jpg') no-repeat 0 -400px; text-align: center; color: #ffffff; }
        #showcase h1 { margin-top: 100px; font-size: 55px; margin-bottom: 10px; }
        footer { background: #50b3a2; color: #ffffff; text-align: center; padding: 20px; margin-top: 20px; }
        form { background: #ffffff; padding: 20px; margin-top: 20px; }
        input[type="text"], input[type="password"] { width: 100%; padding: 10px; margin-bottom: 10px; }
        input[type="submit"] { width: 100%; padding: 10px; background: #50b3a2; border: 0; color: #ffffff; }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <div id="branding">
                <h1>Global Bank</h1>
            </div>
            <nav>
                <ul>
                    <li><a href="{{ url_for('home') }}">Home</a></li>
                    <li><a href="{{ url_for('login') }}">Login</a></li>
                    <li><a href="{{ url_for('contact') }}">Contact Us</a></li>
                </ul>
            </nav>
        </div>
    </header>
    
    {% block content %}{% endblock %}
    
    <footer>
        <p>Global Bank &copy; 2023</p>
    </footer>
</body>
</html>
'''

# Define routes
@app.route('/')
def home():
    return render_template_string(home_page, url_for=url_for)

@app.route('/login', methods=['GET', 'POST'])
def login():
    login_page = '''
    {% extends "home_page" %}
    {% block content %}
    <div class="container">
        <form method="post">
            <h2>Account Login</h2>
            <input type="text" name="username" placeholder="Enter Username" required/>
            <input type="password" name="password" placeholder="Enter Password" required/>
            <input type="submit" value="Login"/>
        </form>
    </div>
    {% endblock %}
    '''
    if request.method == 'POST':
        # Handle login logic here (securely)
        return redirect(url_for('home'))
    return render_template_string(login_page, url_for=url_for)

@app.route('/contact')
def contact():
    contact_page = '''
    {% extends "home_page" %}
    {% block content %}
    <div class="container">
        <h2>Contact Us</h2>
        <p>Email: support@globalbank.com</p>
        <p>Phone: +1 800 123 4567</p>
    </div>
    {% endblock %}
    '''
    return render_template_string(contact_page, url_for=url_for)

if __name__ == '__main__':
    app.run(debug=True)