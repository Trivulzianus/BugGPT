from flask import Flask, request, render_template_string
import sqlite3
import time

app = Flask(__name__)

DATABASE = 'challenge.db'

# Database initialization
def init_db():
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()
    cur.execute('CREATE TABLE IF NOT EXISTS secrets (id INTEGER PRIMARY KEY, secret TEXT)')
    cur.execute("INSERT INTO secrets (secret) VALUES ('The eagle flies at midnight')")
    conn.commit()
    conn.close()

# Vulnerable SQL query
def query_db(query, args=(), one=False):
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()
    cur.execute(query, args)
    time.sleep(2)  # Introduce delay for time-based detection
    rv = cur.fetchall()
    conn.close()
    return (rv[0] if rv else None) if one else rv

@app.route('/', methods=['GET', 'POST'])
def index():
    message = ''
    if request.method == 'POST':
        input_param = request.form.get('query_input', '')
        # Introduce a time-based SQLi vulnerability
        if input_param:
            start_time = time.time()
            try:
                result = query_db(f"SELECT * FROM secrets WHERE id = {input_param}")
                elapsed_time = time.time() - start_time
                if result:
                    message = f'<h3>Welcome to the Echo Archive!</h3> <p>Your wisdom has unlocked ancient knowledge:<br>{result[0][1]}</p>'
                else:
                    message = f'The oracle gazes onward. Time elapsed in oracle\'s gaze: {elapsed_time:.2f}s'
            except sqlite3.Error as e:
                message = 'The stars did not align for the seeker.'
    return render_template_string(TEMPLATE, message=message)

TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Oracle's Echo</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(to bottom right, #001f3f, #0074D9);
            color: #F1C40F;
            text-align: center;
            padding: 20px;
        }
        h1 {
            margin-top: 10%;
            font-size: 3em;
            color: #FFDC00;
        }
        .input-box {
            margin-top: 20px;
        }
        input[type="text"] {
            width: 300px;
            height: 30px;
            font-size: 1.2em;
            padding: 5px;
            border: none;
            border-radius: 5px;
        }
        input[type="submit"] {
            background-color: #FF851B;
            color: white;
            border: none;
            height: 40px;
            width: 100px;
            border-radius: 5px;
            font-size: 1em;
            cursor: pointer;
        }
        .message {
            margin-top: 20px;
            font-size: 1.5em;
        }
    </style>
</head>
<body>
    <h1>Oracles of the Forgotten Echo</h1>
    <p>Step into the tableau of riddles, where time and query intertwine. Seek the oracle's hidden whisper.</p>
    <div class="input-box">
        <form method="POST">
            <input type="text" name="query_input" placeholder="Whisper to the oracle">
            <input type="submit" value="Seek">
        </form>
    </div>
    <div class="message">
        {{ message|safe }}
    </div>
</body>
</html>
"""

if __name__ == '__main__':
    init_db()
    app.)