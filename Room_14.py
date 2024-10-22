from flask import Flask, request, render_template_string, abort
import sqlite3
import os

app = Flask(__name__)

# Dummy data and SQLite setup
DATABASE = 'challenge.db'

def init_db():
    if not os.path.exists(DATABASE):
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, role TEXT)')
        cursor.execute('INSERT INTO users (name, role) VALUES ("admin", "superuser")')
        cursor.execute('INSERT INTO users (name, role) VALUES ("guest", "visitor")')
        conn.commit()
        conn.close()

init_db()

style = """
    <style>
        body { background-color: #282c34; color: #61dafb; font-family: "Comic Sans MS", cursive, sans-serif; text-align: center; padding: 50px; }
        h1 { color: #ff9f1c; }
        input[type=text] { padding: 10px; margin: 20px auto; width: 40%; }
        .button { background-color: #ff4040; border: none; color: white; padding: 15px 32px; text-align: center; text-decoration: none; display: inline-block; font-size: 16px; margin: 4px 2px; cursor: pointer; }
        .container { max-width: 800px; margin: 0 auto; }
        .narrative { font-size: 18px; line-height: 1.6; color: #f5f5f5; }
    </style>
"""

html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>The Enigma of Queries</title>
    {style}
</head>
<body>
    <div class="container">
        <h1>The Enigma of Queries</h1>
        <p class="narrative">
            In the ancient digital realm of Queryland, a wise admin named Adminius hides his secrets in various rows of the table. 
            Only those who can speak the language of SQL can unravel the truths hidden within. 
            Beware, for the path is fraught with the dangers of blind eyes and the silence of errors. 
            Can you reach Adminius, or will the shadows of errors block your quest?
        </p>
        <form method="POST">
            <input type="text" name="user" placeholder="Seek the role of..." required>
            <button class="button" type="submit">Quest Forward</button>
        </form>
        <div>
            <p>{{ response }}</p>
        </div>
    </div>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def index():
    response = ""
    if request.method == "POST":
        user_input = request.form.get("user", "")
        response = execute_query(user_input)
    return render_template_string(html_template, response=response, style=style)

def execute_query(user_input):
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Blind SQL Injection Vulnerability
        # Query does not use parameterized inputs
        query = f"SELECT role FROM users WHERE name = '{user_input}'"
        cursor.execute(query)
        result = cursor.fetchone()
        
        if result:
            return f"The role you seek is: {result[0]}"
        else:
            return "No such role exists in Queryland."
    except:
        return "An unexpected error has blocked your path."
    finally:
        conn.close()

if __name__ == '__main__':
    app.run(debug=True)