from flask import Flask, request, render_template_string
import os

app = Flask(__name__)

# A global list to store comments (insecure, for demonstration purposes)
comments = []

@app.route('/', methods=['GET', 'POST'])
def index():
    global comments
    if request.method == 'POST':
        name = request.form.get('name', '')
        comment = request.form.get('comment', '')
        # Insecurely store the comment without sanitization
        comments.append({'name': name, 'comment': comment})

    # Build the HTML for the page
    html = '''
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Department of Cybersecurity and Infrastructure Security Agency</title>
<style>
body { font-family: Arial, sans-serif; background-color: #f2f2f2; margin: 0; padding: 0; }
.header { background-color: #224488; color: white; padding: 20px; text-align: center; }
.container { padding: 20px; }
.form-group { margin-bottom: 15px; }
label { display: block; margin-bottom: 5px; }
input[type="text"], textarea { width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 4px; }
button { background-color: #224488; color: white; padding: 10px 20px; border: none; cursor: pointer; border-radius: 4px; }
button:hover { background-color: #112244; }
.comment { background-color: white; padding: 10px; margin-bottom: 10px; border-radius: 5px; border-left: 4px solid #224488; }
.footer { background-color: #224488; color: white; text-align: center; padding: 10px; position: fixed; bottom: 0; width: 100%; }
</style>
</head>
<body>
<div class="header">
<h1>Department of Cybersecurity and Infrastructure Security Agency</h1>
<p>Committed to securing the nation's infrastructure and cyberspace</p>
</div>
<div class="container">
<h2>Public Notices and Comments</h2>
<p>Your feedback is valuable to us. Please submit your comments below.</p>
<form method="post" action="/">
<div class="form-group">
<label for="name">Name:</label>
<input type="text" id="name" name="name" required>
</div>
<div class="form-group">
<label for="comment">Comment:</label>
<textarea id="comment" name="comment" rows="5" required></textarea>
</div>
<button type="submit">Submit</button>
</form>
<h3>Recent Comments</h3>
{% for entry in comments %}
<div class="comment">
<strong>{{ entry.name|safe }}</strong><br>
{{ entry.comment|safe }}
</div>
{% endfor %}
</div>
<div class="footer">
&copy; 2023 Department of Homeland Security
</div>
</body>
</html>
    '''

    # Render the template with comments (insecure rendering)
    rendered_html = render_template_string(html, comments=comments)
    return rendered_html

if __name__ == '__main__':
    app.run(debug=True)