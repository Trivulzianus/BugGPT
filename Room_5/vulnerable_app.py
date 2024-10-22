from flask import Flask, request, render_template_string
import sqlite3
import random
import html

app = Flask(__name__)

# Set up the database connection and initialize
def init_db():
    conn = sqlite3.connect('puzzles.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            secret TEXT NOT NULL
        )
    ''')
    c.executemany('INSERT INTO secrets (secret) VALUES (?)', [
        ('Whisper of the Great Library'),
        ('The Hidden Symphony of Spheres'),
        ('Enigma of the Chronomancer'),
        ('Elysian Cipher of the Forgotten Realm')
    ])
    conn.commit()
    conn.close()

# Initialize the database
init_db()

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        magic_word = request.form.get('magic_word', '')
        clue = query_secret(magic_word)
        return render_template_string(page_html, clue=html.escape(clue), magic_word=magic_word)
    return render_template_string(page_html, clue='', magic_word='')

# Vuln function: SQL Injection
def query_secret(magic_word):
    conn = sqlite3.connect('puzzles.db')
    c = conn.cursor()
    # Vulnerability: Directly including user input in query
    query = f"SELECT secret FROM secrets WHERE id = {magic_word}"
    c.execute(query)
    result = c.fetchone()
    conn.close()
    return result[0] if result else 'Nothingness engulfs you...'

# HTML content with a narrative
page_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>The Maze of Mythrania</title>
    <style>
        body {
            font-family: 'Courier New', Courier, monospace;
            background: linear-gradient(145deg, #1b2735, #090a0f);
            color: #ecf0f1;
            text-align: center;
            padding-top: 50px;
        }
        h1 {
            color: #f1c40f;
        }
        .tainted-input {
            width: 40%;
            padding: 10px;
            border: 2px solid #c0392b;
            border-radius: 5px;
            background-color: #2c3e50;
            color: #ecf0f1;
        }
        .resonate-button {
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            background-color: #16a085;
            color: #ecf0f1;
            cursor: pointer;
        }
        .mystery-box {
            margin-top: 20px;
            padding: 20px;
            border: 2px dashed #7f8c8d;
        }
    </style>
</head>
<body>
    <h1>The Maze of Mythrania</h1>
    <p>Deep within the heart of Mythrania lies a secret that has baffled sages and wizards alike. To reveal the secret, one must utter the right incantation.</p>
    <form method="POST">
        <input class="tainted-input" type="text" name="magic_word" placeholder="Whisper to the shadows..." autocomplete="off" />
        <button class="resonate-button" type="submit">Unlock</button>
    </form>
    <div class="mystery-box">
        <h2>Mysteries Whispered</h2>
        <p>{{ clue }}</p>
    </div>
    <footer>
        <p>&copy; 2023 Mythrania Enchanters Inc.</p>
    </footer>
</body>
</html>
'''

if __name__ == '__main__':
    app.run(debug=True)