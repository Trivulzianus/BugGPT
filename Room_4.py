from flask import Flask, request, render_template_string
import sqlite3
import random

app = Flask(__name__)

# Database setup
def init_db():
    conn = sqlite3.connect('challenging_app.db')
    cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS secrets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    secret TEXT NOT NULL)''')
    if cur.execute('SELECT COUNT(*) FROM secrets').fetchone()[0] == 0:
        secrets = ['CheshireCat', 'MadHatter', 'QueenOfHearts', 'MarchHare']
        for secret in secrets:
            cur.execute('INSERT INTO secrets (secret) VALUES (?)', (secret,))
    conn.commit()
    conn.close()

init_db()

# Color palette
colors = ['#FF5733', '#33FFCE', '#FF33F5', '#33FF57', '#FF8F33', '#FFE733']

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Journey Through Wonderland</title>
    <style>
        body {{
            background-color: #282c34;
            color: #ffffff;
            font-family: "Courier New", Courier, monospace;
            text-align: center;
            padding: 50px;
        }}
        h1 {{
            color: {color1};
        }}
        .secret-container {{
            background-color: {color2};
            padding: 20px;
            border-radius: 15px;
            box-shadow: 0px 0px 10px #000;
            margin: 20px;
        }}
    </style>
</head>
<body>
    <h1>Welcome to the Enigmatic Wonderland!</h1>
    <p>Beyond this realm lies secrets hidden from the ordinary eye, bound by logic, and entwining with madness. Will you dare to find them?</p>
    <div class="secret-container">
        <form method="post">
            <label for="secret_id">Enter a number, but choose wisely:</label><br><br>
            <input type="text" id="secret_id" name="secret_id"><br><br>
            <button type="submit">Reveal the Secret</button>
        </form>
    </div>
    <p>{secret}</p>
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def index():
    random.shuffle(colors)
    color1, color2 = colors[0], colors[1]
    secret_message = ""

    if request.method == 'POST':
        secret_id = request.form.get('secret_id', '')

        conn = sqlite3.connect('challenging_app.db')
        cur = conn.cursor()
        try:
            # Here we simulate blind sqli by delaying on true conditions
            query = f"SELECT secret FROM secrets WHERE id = {secret_id}"
            cur.execute(query)
            result = cur.fetchone()

            if result:
                secret_message = f"✨ The secret you venture for: {result[0]} ✨"
            else:
                secret_message = "❌ Alas! You've wandered down the wrong rabbit hole! ❌"

        except sqlite3.Error:
            secret_message = "❌ Alas! You've wandered down the wrong rabbit hole! ❌"
        finally:
            conn.close()

    return render_template_string(HTML_TEMPLATE, color1=color1, color2=color2, secret=secret_message)

if __name__ == '__main__':
    app.run(debug=True)