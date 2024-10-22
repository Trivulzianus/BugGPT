from flask import Flask, render_template_string, request
import sqlite3

app = Flask(__name__)

# SQLite database setup with some initial data
def init_db():
    conn = sqlite3.connect('enigmatic_tome.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS library (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            author TEXT NOT NULL,
            secrets TEXT NOT NULL
        )
    ''')
    # Books with secrets
    initial_books = [
        ("Atlas of Infinity", "Nova Astra", "The secret star coordinates are hidden under the author's pen name."),
        ("Cryptic Codex", "Zephyrus Borealis", "Encoded within are the whispers of the Northern Lights.")
    ]
    cursor.executemany('INSERT INTO library (title, author, secrets) VALUES (?, ?, ?)', initial_books)
    conn.commit()
    conn.close()

init_db()

# HTML Template for rendering
html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>The Enigmatic Tome</title>
    <style>
        body { background-color: #2e2b2b; color: #e0dfdc; font-family: 'Courier New', Courier, monospace; }
        .container { text-align: center; padding: 50px; }
        .mystical-glow { text-shadow: 0 0 5px #88e1f2, 0 0 10px #88e1f2, 0 0 15px #88e1f2; }
        input[type="text"] { border: 2px solid #88e1f2; padding: 10px; width: 300px; }
        input[type="submit"] { background-color: #88e1f2; color: #2e2b2b; padding: 10px 20px; border: none; cursor: pointer; }
        input[type="submit"]:hover { background-color: #5bbcd4; }
        .book-display { border: 1px solid #88e1f2; padding: 20px; margin: 20px; }
    </style>
</head>
<body>

<div class="container">
    <h1 class="mystical-glow">Welcome to the Enigmatic Tome</h1>
    <p>A library filled with cryptic books awaits those who seek the whispered secrets of the universe.</p>
    <form method="POST">
        <input type="text" name="search" placeholder="Search by book title or author" />
        <input type="submit" value="Search" />
    </form>
    {% if results %}
        <h2 class="mystical-glow">Books Found:</h2>
        {% for book in results %}
        <div class="book-display">
            <h3>{{ book[1] }} by {{ book[2] }}</h3>
            <p>{{ book[3] }}</p>
        </div>
        {% endfor %}
    {% endif %}
</div>

</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def home():
    results = None
    if request.method == 'POST':
        search_term = request.form.get('search', '')
        conn = sqlite3.connect('enigmatic_tome.db')
        cursor = conn.cursor()
        
        # Intentionally vulnerable SQL query
        query = f"SELECT * FROM library WHERE title LIKE '%{search_term}%' OR author LIKE '%{search_term}%'"
        try:
            cursor.execute(query)
            results = cursor.fetchall()
        except sqlite3.Error as e:
            results = [("Error", str(e), "An error occurred while reading the tome's secrets.")]
        
        conn.close()
    
    return render_template_string(html_template, results=results)

if __name__ == '__main__':
    app.run(debug=True)