from flask import Flask, request, render_template_string, redirect, url_for

app = Flask(__name__)

# Simulated database with user information
users_db = {
    '1': {'name': 'Alice', 'balance': '5000', 'secret': 'LovesCats'},
    '2': {'name': 'Bob', 'balance': '3000', 'secret': 'EnjoysSkydiving'},
    '3': {'name': 'Charlie', 'balance': '7000', 'secret': 'ChessChampion'}
}

# HTML Template for rendering
template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>The Enchanted Bank</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(to bottom right, #FF7E5F, #FEB47B);
            color: #333;
            text-align: center;
            padding: 20px;
        }
        .container {
            background-color: #fff;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            max-width: 600px;
            margin: 40px auto;
        }
        h1 {
            color: #FF7E5F;
        }
        .user-info {
            margin-top: 20px;
            text-align: left;
        }
        .hidden {
            color: #fff;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>The Enchanted Bank</h1>
        <p>Welcome to the bank where fortunes are made and secrets are kept.<br>Can you discover the hidden truths within?</p>
        <form method="get" action="/user">
            <input type="text" name="user_id" placeholder="Enter your User ID" required>
            <button type="submit">Access Account</button>
        </form>
        {% if user %}
        <div class="user-info">
            <p><strong>Name:</strong> {{ user.name }}</p>
            <p><strong>Account Balance:</strong> ${{ user.balance }}</p>
            <p class="hidden"><strong>Secret:</strong> {{ user.secret }}</p>
        </div>
        {% endif %}
    </div>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(template)

@app.route('/user')
def user_profile():
    user_id = request.args.get('user_id')
    user = users_db.get(user_id)
    return render_template_string(template, user=user)

if __name__ == '__main__':
    app.run(debug=True)