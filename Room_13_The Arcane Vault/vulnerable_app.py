from flask import Flask, render_template_string, request, redirect, url_for
import random

app = Flask(__name__)

page_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>The Arcane Vault</title>
    <style>
        body {
            background: linear-gradient(to right, #1a2a6c, #b21f1f, #fdbb2d);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            color: white;
            padding: 20px;
        }
        .artifact-entry {
            background-color: rgba(255, 255, 255, 0.2);
            margin-bottom: 10px;
            padding: 10px;
            border-radius: 8px;
            box-shadow: 3px 3px 5px #00000050;
            position: relative;
        }
        .artifact-content {
            color: white;
        }
        .artifact-title {
            font-size: 1.2em;
            font-weight: bold;
        }
        .artifact-id {
            position: absolute;
            font-size: 0.8em;
            color: grey;
            top: 5px;
            right: 10px;
        }
        .add-form {
            margin-top: 20px;
            text-align: center;
        }
        input[type="text"], textarea {
            width: 80%;
            padding: 10px;
            margin-top: 10px;
            border: none;
            border-radius: 5px;
            box-shadow: 3px 3px 5px #00000050;
        }
        input[type="submit"] {
            background-color: #b21f1f;
            color: white;
            padding: 10px 20px;
            margin-top: 10px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            box-shadow: 3px 3px 5px #00000050;
            transition: background-color 0.3s ease;
        }
        input[type="submit"]:hover {
            background-color: #fdbb2d;
        }
    </style>
</head>
<body>
    <h1 style="text-align: center; font-size: 2em;">The Arcane Vault: A Treasury of Mystical Artifacts</h1>
    <p>Welcome to The Arcane Vault! Here, seekers of the arcane can share and discover mystical artifacts lost in the sands of time. Please add your entries to enlighten the world.</p>
    
    <div class="artifacts-list">
        {% for artifact in artifacts %}
        <div class="artifact-entry">
            <div class="artifact-id">#{{artifact["id"]}}</div>
            <div class="artifact-title">{{artifact["title"]}}</div>
            <div class="artifact-content">{{artifact["content"]|safe}}</div>
        </div>
        {% endfor %}
    </div>

    <div class="add-form">
        <form action="{{ url_for('add_artifact') }}" method="post">
            <input type="text" name="title" placeholder="Artifact Title" required><br>
            <textarea name="content" placeholder="Artifact Description" rows="4" required></textarea><br>
            <input type="submit" value="Share Your Artifact">
        </form>
    </div>
</body>
</html>
"""

# In-memory storage for the artifacts
artifacts_storage = [
    {"id": 1, "title": "The Stone of Ereshkigal", "content": "A dark stone said to resonate with the energy of the underworld."},
    {"id": 2, "title": "The Chalice of Gwydion", "content": "This silver chalice allegedly grants visions to those who drink from it."}
]

@app.route('/')
def index():
    return render_template_string(page_template, artifacts=artifacts_storage)

@app.route('/add', methods=['POST'])
def add_artifact():
    new_id = max([artifact['id'] for artifact in artifacts_storage]) + 1 if artifacts_storage else 1
    new_artifact = {
        "id": new_id,
        "title": request.form['title'],
        "content": request.form['content']
    }
    artifacts_storage.append(new_artifact)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)