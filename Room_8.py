from flask import Flask, request, render_template_string
import sqlite3
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

# Create an in-memory SQLite database for the challenge.
def init_db():
    conn = sqlite3.connect('challenging.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS explorers (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            secret TEXT NOT NULL
        )
    ''')
    c.execute("INSERT INTO explorers (name, secret) VALUES ('Marco Polo', 'Silk Road Secrets')")
    c.execute("INSERT INTO explorers (name, secret) VALUES ('Ibn Battuta', 'Sands of Saharan Mysteries')")
    c.execute("INSERT INTO explorers (name, secret) VALUES ('Zheng He', 'Admiral of the Starry Sea')")
    conn.commit()
    conn.close()

# Initialize the database
init_db()

@app.route('/', methods=['GET', 'POST'])
def index():
    message = ''
    if request.method == 'POST':
        search_query = request.form.get('adventure', '')
        conn = sqlite3.connect('challenging.db')
        c = conn.cursor()
        
        # Purposefully vulnerable SQL query
        query = f"SELECT secret FROM explorers WHERE name = '{search_query}'"
        
        try:
            c.execute(query)
            secrets = c.fetchall()
            if secrets:
                message = f"An ancient secret awaits: {secrets[0][0]}"
            else:
                message = "The adventure you seek is shrouded in mystery, try again."
        except sqlite3.Error as e:
            message = f"An error lurks in the shadows: {str(e)}"
        finally:
            conn.close()
    
    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Mystical Quests</title>
        <style>
            body {
                background: linear-gradient(to right, #4facfe, #00f2fe);
                color: #333;
                font-family: Arial, sans-serif;
                text-align: center;
                padding: 20px;
            }
            header {
                font-size: 2.5em;
                margin-bottom: 20px;
            }
            .container {
                background: white;
                padding: 30px;
                border-radius: 8px;
                box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
                display: inline-block;
            }
            input[type="text"] {
                width: 300px;
                padding: 10px;
                font-size: 1.1em;
                border-radius: 4px;
                border: 1px solid #ccc;
                margin-bottom: 20px;
            }
            input[type="submit"] {
                padding: 10px 20px;
                font-size: 1.1em;
                background: #4facfe;
                color: white;
                border: none;
                border-radius: 4px;
                cursor: pointer;
                transition: background 0.3s;
            }
            input[type="submit"]:hover {
                background: #3a8fc0;
            }
        </style>
    </head>
    <body>
        <header>Mystical Quests: Unearth the Lost Secrets</header>
        <div class="container">
            <form method="post">
                <input type="text" name="adventure" placeholder="Name your explorer...">
                <br>
                <input type="submit" value="Venture forth">
            </form>
            <p>{{ message }}</p>
        </div>
    </body>
    </html>
    """
    
    return render_template_string(html_template, message=message)

if __name__ == '__main__':
    app.run(debug=True)