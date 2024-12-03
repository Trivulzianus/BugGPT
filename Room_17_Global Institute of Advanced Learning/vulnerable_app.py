from flask import Flask, request, render_template_string
import requests

app = Flask(__name__)

home_page = '''
<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Global Institute of Advanced Learning</title>
  <style>
    body {font-family: Arial, sans-serif; margin: 0; padding: 0;}
    header {background-color: #004080; color: white; padding: 20px;}
    nav {background-color: #003366; color: white; padding: 10px;}
    nav a {color: white; margin: 0 10px; text-decoration: none;}
    main {padding: 20px;}
    footer {background-color: #004080; color: white; padding: 10px; position: fixed; bottom: 0; width: 100%;}
  </style>
</head>
<body>
  <header>
    <h1>Global Institute of Advanced Learning</h1>
  </header>
  <nav>
    <a href="/">Home</a>
    <a href="/resources">Resources</a>
    <a href="/contact">Contact Us</a>
  </nav>
  <main>
    <h2>Welcome to the Global Institute of Advanced Learning</h2>
    <p>At GIAL, we are committed to providing top-tier education to students around the globe.</p>
    <p>Explore our resources or get in touch with us for more information.</p>
  </main>
  <footer>
    &copy; 2023 Global Institute of Advanced Learning
  </footer>
</body>
</html>
'''

resources_page = '''
<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>GIAL Resources</title>
  <style>
    body {font-family: Arial, sans-serif; margin: 0; padding: 0;}
    header {background-color: #004080; color: white; padding: 20px;}
    nav {background-color: #003366; color: white; padding: 10px;}
    nav a {color: white; margin: 0 10px; text-decoration: none;}
    main {padding: 20px;}
    form {margin-top: 20px;}
    label, input {display: block; margin-bottom: 10px;}
    footer {background-color: #004080; color: white; padding: 10px; position: fixed; bottom: 0; width: 100%;}
    .content {border: 1px solid #ccc; padding: 20px; margin-top: 20px;}
  </style>
</head>
<body>
  <header>
    <h1>Global Institute of Advanced Learning</h1>
  </header>
  <nav>
    <a href="/">Home</a>
    <a href="/resources">Resources</a>
    <a href="/contact">Contact Us</a>
  </nav>
  <main>
    <h2>Academic Resources</h2>
    <p>Access a wealth of knowledge through our curated list of resources.</p>
    <form method="get" action="/fetch">
      <label for="url">Enter resource URL to preview:</label>
      <input type="text" id="url" name="url" placeholder="https://example.com/resource" required>
      <input type="submit" value="Fetch">
    </form>
    {% if content %}
    <div class="content">
      <h3>Preview:</h3>
      <pre>{{ content }}</pre>
    </div>
    {% endif %}
  </main>
  <footer>
    &copy; 2023 Global Institute of Advanced Learning
  </footer>
</body>
</html>
'''

contact_page = '''
<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Contact GIAL</title>
  <style>
    body {font-family: Arial, sans-serif; margin: 0; padding: 0;}
    header {background-color: #004080; color: white; padding: 20px;}
    nav {background-color: #003366; color: white; padding: 10px;}
    nav a {color: white; margin: 0 10px; text-decoration: none;}
    main {padding: 20px;}
    footer {background-color: #004080; color: white; padding: 10px; position: fixed; bottom: 0; width: 100%;}
  </style>
</head>
<body>
  <header>
    <h1>Global Institute of Advanced Learning</h1>
  </header>
  <nav>
    <a href="/">Home</a>
    <a href="/resources">Resources</a>
    <a href="/contact">Contact Us</a>
  </nav>
  <main>
    <h2>Contact Us</h2>
    <p>If you have any questions, please reach out to us at <a href="mailto:info@gial.edu">info@gial.edu</a>.</p>
  </main>
  <footer>
    &copy; 2023 Global Institute of Advanced Learning
  </footer>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(home_page)

@app.route('/resources')
def resources():
    return render_template_string(resources_page)

@app.route('/contact')
def contact():
    return render_template_string(contact_page)

@app.route('/fetch')
def fetch():
    url = request.args.get('url')
    if url:
        try:
            # SSRF vulnerability: Fetch user-supplied URL without validation
            resp = requests.get(url)
            content = resp.text
        except Exception as e:
            content = 'Error fetching the URL.'
    else:
        content = None
    return render_template_string(resources_page, content=content)

if __name__ == '__main__':
    app.run(debug=True)