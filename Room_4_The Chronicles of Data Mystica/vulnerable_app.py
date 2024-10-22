from flask import Flask, request, render_template_string, redirect, url_for

app = Flask(__name__)

# Sample data simulating sensitive information that should be protected
mock_data = {
    1: {'username': 'alice', 'secret': 'Alice loves cats'},
    2: {'username': 'bob', 'secret': 'Bob hates carrots'},
    3: {'username': 'charlie', 'secret': 'Charlie has a secret garden'}
}

@app.route('/')
def home():
    return render_template_string(HOME_PAGE_HTML)

@app.route('/user/<int:user_id>')
def user_profile(user_id):
    user_info = mock_data.get(user_id)
    if user_info:
        return render_template_string(PROFILE_PAGE_HTML, user=user_info)
    else:
        return redirect(url_for('home'))

# HOME_PAGE_HTML contains the narrative and a link that could be exploited
HOME_PAGE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>The Chronicles of Data Mystica</title>
    <style>
        body {
            background-image: linear-gradient(to right, #ff7e5f, #feb47b);
            color: #333;
            font-family: 'Arial', sans-serif;
            text-align: center;
            padding: 20px;
        }
        h1 {
            color: #fff;
            margin-bottom: 20px;
        }
        .story {
            background: rgba(255, 255, 255, 0.8);
            padding: 20px;
            border-radius: 10px;
            display: inline-block;
        }
        .button {
            background: #fff;
            color: #ff7e5f;
            text-decoration: none;
            padding: 10px 20px;
            border-radius: 5px;
            font-weight: bold;
            transition: background 0.3s, color 0.3s;
        }
        .button:hover {
            background: #ff7e5f;
            color: #fff;
        }
    </style>
</head>
<body>
    <h1>The Chronicles of Data Mystica</h1>
    <div class="story">
        <p>Welcome, brave adventurer, to the mystical land of Data Mystica! In this lush digital world, secrets are hidden beneath veils of complexity, awaiting those daring enough to uncover them.</p>
        <p>Your journey starts here. As a fledgling seeker of truths, your first task is to discover the hidden secrets of the inhabitants of Data Mystica. Will you unravel the mysteries that elude so many?</p>
        <p>A wise sage offers you a clue, a glimpse into a life beyond your own:</p>
        <a class="button" href="{{ url_for('user_profile', user_id=1) }}">Glimpse the Life of a Sage</a>
    </div>
</body>
</html>
"""

# PROFILE_PAGE_HTML displays information for a specific user profile
PROFILE_PAGE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ user.username }}'s Realm</title>
    <style>
        body {
            background-image: linear-gradient(to left, #36d1dc, #5b86e5);
            color: #fff;
            font-family: 'Arial', sans-serif;
            text-align: center;
            padding: 20px;
        }
        .profile {
            background: rgba(255, 255, 255, 0.2);
            padding: 20px;
            border-radius: 10px;
            display: inline-block;
        }
        h1 {
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <h1>{{ user.username }}'s Realm</h1>
    <div class="profile">
        <p>Welcome to the realm of {{ user.username }}.</p>
        <p><strong>Secret:</strong> {{ user.secret }}</p>
        <p><a href="{{ url_for('home') }}" style="color: #fff; text-decoration: underline;">Return to Data Mystica</a></p>
    </div>
</body>
</html>
"""

if __name__ == '__main__':
    app.run(debug=True)