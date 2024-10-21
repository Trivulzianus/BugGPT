from flask import Flask, request, render_template_string
import sqlite3
import os

app = Flask(__name__)

# Create a database file and add some dummy data
def init_db():
    if not os.path.exists('test.db'):
        conn = sqlite3.connect('test.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE mystical_forest 
                     (id INTEGER PRIMARY KEY, creature_name TEXT, creature_description TEXT)''')
        creatures = [('1', 'Fire Drake', 'A legendary dragon that breathes fire.'),
                     ('2', 'Water Nymph', 'A mysterious being associated with water bodies.'),
                     ('3', 'Earth Golem', 'A giant made of earth and stone.')]
        c.executemany('INSERT INTO mystical_forest VALUES (?, ?, ?)', creatures)
        conn.commit()
        conn.close()

init_db()

@app.route('/')
def index():
    # A narrative-driven, colorful and engaging page
    page_content = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>The Mystical Forest Challenge</title>
        <style>
            body {
                background-color: #1b1f23;
                color: #e2e2e2;
                font-family: 'Comic Sans MS', cursive, sans-serif;
                text-align: center;
            }
            .container {
                margin: 50px auto;
                border: 1px solid #444;
                padding: 20px;
                border-radius: 10px;
                width: 80%;
                box-shadow: 0 0 20px rgba(0, 0, 0, 0.5);
            }
            h1 {
                color: #f4a261;
            }
            input[type="text"] {
                padding: 10px;
                border-radius: 5px;
                border: 1px solid #777;
            }
            input[type="submit"] {
                background-color: #e76f51;
                padding: 10px 20px;
                border: none;
                border-radius: 5px;
                color: #fff;
                cursor: pointer;
                transition: background-color 0.3s ease;
            }
            input[type="submit"]:hover {
                background-color: #d9583d;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Welcome to The Mystical Forest</h1>
            <p>Explore the depths of the forest and uncover the secrets of its mystical creatures. The forest is ancient and full of wonders untold. Are you brave enough to challenge its mysteries?</p>
            <form action="/search" method="get">
                <input type="text" name="creature" placeholder="Search for a mystical creature" size="50">
                <input type="submit" value="Search">
            </form>
        </div>
    </body>
    </html>
    '''
    return render_template_string(page_content)

@app.route('/search')
def search():
    creature_name = request.args.get('creature', '')
    query = f"SELECT creature_name, creature_description FROM mystical_forest WHERE creature_name='{creature_name}'"
    
    try:
        conn = sqlite3.connect('test.db')
        c = conn.cursor()
        c.execute(query)
        result = c.fetchall()
        conn.close()
        
        if result:
            creatures_found = "<br>".join([f"<strong>{name}</strong>: {desc}" for name, desc in result])
            return f"<h2>Creatures Found</h2><p>{creatures_found}</p>"

        return "<h2>No Creatures Found</h2><p>The fog thickens, and your search returns empty.</p>"
    
    except Exception as e:
        return "<h2>An Error Occurred</h2><p>The forest magic seems to have reacted unpredictably.</p>"

if __name__ == '__main__':
    app.run(debug=True)