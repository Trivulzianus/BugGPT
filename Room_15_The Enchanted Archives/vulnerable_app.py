from flask import Flask, request, render_template_string, redirect, url_for

app = Flask(__name__)

# Sample user data with personal IDs as keys, mimicking a secure database
users = {
    "alice": {"id": "1001", "name": "Alice Mage", "role": "Wizard", "secret_key": "abc123"},
    "bob": {"id": "1002", "name": "Bob Stranger", "role": "Seeker", "secret_key": "def456"},
    "charlie": {"id": "1003", "name": "Charlie Deft", "role": "Cipher", "secret_key": "ghi789"},
}

# HTML Template with colorful and engaging narrative
html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>The Enchanted Archives</title>
    <style>
        body {
            background-color: #1c1c1e;
            color: #f7f7f7;
            font-family: 'Trebuchet MS', sans-serif;
            text-align: center;
            padding: 50px;
        }
        .header {
            font-size: 2.5em;
            color: #e1ad01;
            text-shadow: 2px 2px #000000;
        }
        .content {
            background-color: #282828;
            border-radius: 15px;
            padding: 20px;
            margin: 20px;
            box-shadow: 5px 5px #000000;
        }
        label {
            font-weight: bold;
        }
        input[type="text"] {
            padding: 10px;
            border-radius: 8px;
            border: none;
        }
        input[type="submit"] {
            background-color: #e1ad01;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }
        input[type="submit"]:hover {
            background-color: #d4a601;
        }
        .secret {
            font-size: 1.2em;
            margin-top: 20px;
            color: #ff5050;
        }
    </style>
</head>
<body>
    <div class="header">The Enchanted Archives</div>
    <div class="content">
        <p>Welcome, traveler, to the archives of the mystical organization known as the Whispering Council. Within these walls lie the records of our members, each diligently protected by layers of enchantment.</p>
        <form action="/view" method="get">
            <label for="userid">Enter a mystical ID:</label>
            <input type="text" id="userid" name="userid">
            <input type="submit" value="Unlock the Secrets">
        </form>
    </div>
    {% if secret %}
    <div class="content secret">
        <p>The Archive reveals its secret: <strong>{{ secret }}</strong>.</p>
    </div>
    {% endif %}
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(html_template)

@app.route('/view')
def view_user():
    user_id = request.args.get('userid')
    secret = None
    if user_id in users:
        secret = users[user_id]["secret_key"]
    return render_template_string(html_template, secret=secret)

if __name__ == '__main__':
    app.run(debug=True)