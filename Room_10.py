from flask import Flask, request, render_template_string
import sqlite3
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

# In-memory SQLite database setup
def init_db():
    conn = sqlite3.connect(':memory:')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE mysterious_table (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            secret_code TEXT,
            reveal TEXT
        )
    ''')
    entries = [
        ('42', 'You have unlocked the secret to the universe!'),
        ('shadow', 'You have found the hidden path in the labyrinth.'),
        ('ancient', 'The artifact is now yours to command.'),
    ]
    c.executemany('INSERT INTO mysterious_table (secret_code, reveal) VALUES (?, ?)', entries)
    conn.commit()
    return conn

@app.route('/', methods=['GET', 'POST'])
def index():
    error_message = ""
    secret_reveal = ""
    if request.method == 'POST':
        code = request.form.get('secret_code', '')
        try:
            # Intentional SQL Injection vulnerability, the challenge:
            query = f"SELECT reveal FROM mysterious_table WHERE secret_code = '{code}'"
            conn = init_db()
            c = conn.cursor()
            c.execute(query)
            result = c.fetchone()

            if result:
                secret_reveal = result[0]
            else:
                error_message = "Alas, the code does not resonate with our records."
        except Exception as e:
            error_message = "A mystic error has occurred."

    # Create colorful and engaging HTML
    page = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>The Enigma of Arcana</title>
        <style>
            body {background: linear-gradient(to right, #00f260, #0575e6);
                  font-family: 'Courier New', Courier, monospace; color: #fff; text-align: center; padding: 5%;}
            h1 {font-size: 3em; margin-bottom: 0.2em;}
            p {font-size: 1.2em; margin: 0.5em;}
            input {padding: 0.5em; font-size: 1.2em; width: 20%; margin: 1em 0;}
            button {padding: 0.5em 1em; font-size: 1.2em; background-color: #0033cc; 
                    border: none; color: white; cursor: pointer;}
            button:hover {background-color: #0055ff;}
        </style>
    </head>
    <body>
        <h1>The Enigma of Arcana</h1>
        <p>Welcome, seeker of the arcane. In the depths of this realm lies an ancient database,
        protected by the venerable guardian known as SQL, which holds the secrets you desire.</p>
        
        <p>Through inscrutable mysteries and uncanny logic, only a code of true power can reveal the knowledge hidden within.</p>
        <form action="/" method="POST">
            <input type="text" name="secret_code" placeholder="Enter the code" required>
            <button type="submit">Reveal</button>
        </form>
        <p>{{ error_message }}</p>
        <h2>{{ secret_reveal }}</h2>
    </body>
    </html>
    """
    return render_template_string(page, error_message=error_message, secret_reveal=secret_reveal)

if __name__ == '__main__':
    app.run(debug=True)