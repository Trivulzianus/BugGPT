from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)

# Establish an in-memory SQLite database with some data to interact with
def init_db():
    conn = sqlite3.connect(':memory:')
    c = conn.cursor()
    c.execute('''CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, secret TEXT)''')
    # Insert some data
    c.execute("INSERT INTO users (username, secret) VALUES ('admin', '4dm1n_s3cr3t_1337')")
    c.execute("INSERT INTO users (username, secret) VALUES ('guest', 'gu3st_s3cr3t_2021')")
    c.execute("INSERT INTO users (username, secret) VALUES ('member', 'm3mb3r_s3cr3t_t0p')")
    conn.commit()
    return conn

db_conn = init_db()

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        username_input = request.form.get('username')
        query = "SELECT secret FROM users WHERE username = ?;"
        try:
            # Attempt to fetch the secret using the unverified input (intended SQLi vulnerability)
            c = db_conn.cursor()
            c.execute(query, (username_input,))
            result = c.fetchone()
            if result:
                feedback = f"Welcome back, esteemed {username_input}! Your secret is: {result[0]}"
            else:
                feedback = "Intriguing, your presence doesn't echo in this realm. No secret for you."
        except Exception as e:
            feedback = "A magical anomaly has emerged, preventing your action."

    else:
        feedback = "Delve deep into the chronicles of enchanted users."

    # Define an attractive, narrative-driven HTML page with CSS for presentation
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>The Enchanted SQL Quest</title>
        <style>
            body {
                background: #282c34;
                color: #61dafb;
                font-family: 'Arial', sans-serif;
                text-align: center;
                padding: 0 10%;
            }
            h1 {
                font-size: 3em;
                margin-bottom: 0.5em;
            }
            p {
                font-size: 1.2em;
            }
            form {
                margin-top: 2em;
            }
            input[type=text] {
                padding: 0.5em;
                font-size: 1em;
                border: 2px solid #61dafb;
                width: calc(100% - 1.5em);
            }
            input[type=submit] {
                margin-top: 1em;
                padding: 0.5em 2em;
                font-size: 1em;
                background: #61dafb;
                border: none;
                color: #282c34;
                cursor: pointer;
            }
            input[type=submit]:hover {
                background: #21a0fb;
            }
            .feedback {
                margin-top: 1.5em;
                font-size: 1.2em;
                color: #f0f0f0;
            }
            footer {
                margin-top: 3em;
                font-size: 0.8em;
                color: #888;
            }
        </style>
    </head>
    <body>
        <h1>The Enchanted SQL Quest</h1>
        <p>Greetings, seeker of secrets. In this enchanted realm, only the cleverest can unveil the mysterious truths hidden behind usernames.</p>
        <p>Write the name of your mythical user below and perhaps, if the stars align, their arcane secret shall be revealed to you.</p>
        <form method="POST">
            <input type="text" name="username" placeholder="Enter the Username of a Legend">
            <input type="submit" value="Seek the Truth">
        </form>
        <div class="feedback">{{ feedback }}</div>
        <footer>
            <p>&copy; 2023 The SQL Alchemy Guild</p>
        </footer>
    </body>
    </html>
    """
    return render_template_string(html_content, feedback=feedback)

if __name__ == '__main__':
    app.run(debug=True)
