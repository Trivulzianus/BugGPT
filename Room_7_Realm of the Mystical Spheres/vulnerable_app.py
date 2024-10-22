from flask import Flask, request, render_template_string
import time
import sqlite3
import random
import string

app = Flask(__name__)

# Database setup with example data
def init_db():
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS mystical_spheres
                      (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                       color TEXT NOT NULL, 
                       power TEXT NOT NULL)''')

    # Insert some data into the table
    spheres = [
        ('Ruby Red', 'Fire Essence'),
        ('Emerald Green', 'Earth Essence'),
        ('Sapphire Blue', 'Water Essence'),
        ('Amethyst Purple', 'Mind Essence')
    ]
    cursor.executemany('INSERT INTO mystical_spheres (color, power) VALUES (?, ?)', spheres)
    conn.commit()
    conn.close()

init_db()

# HTML template with a narrative
html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Realm of the Mystical Spheres</title>
    <style>
        body { background-color: #2e004f; color: #ffffff; font-family: Arial, sans-serif; padding: 20px; }
        .header { text-align: center; }
        .sphere { margin: 20px 0; padding: 10px; border-radius: 10px; }
        .ruby { background-color: #ff0000; }
        .emerald { background-color: #00ff40; }
        .sapphire { background-color: #0000ff; }
        .amethyst { background-color: #9400d3; }
        .search-box { margin-top: 30px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>The Realm of the Mystical Spheres</h1>
        <p>Explore the secrets of the mystical spheres, each containing ancient powers from another world.</p>
    </div>
    <div class="spheres">
        <div class="sphere ruby">Ruby Red: Fire Essence</div>
        <div class="sphere emerald">Emerald Green: Earth Essence</div>
        <div class="sphere sapphire">Sapphire Blue: Water Essence</div>
        <div class="sphere amethyst">Amethyst Purple: Mind Essence</div>
    </div>
    <div class="search-box">
        <form method="GET" action="/search">
            <label for="query">Seek the hidden truth within the sphere colors:</label>
            <input type="text" id="query" name="query" placeholder="Enter sphere color..." required>
            <button type="submit">Summon</button>
        </form>
    </div>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(html_template)

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query', '')
    
    # Introduce a vulnerable query
    try:
        conn = sqlite3.connect('example.db')
        cursor = conn.cursor()

        # Simulate a time-based SQL injection vulnerability
        # This is intentionally vulnerable: using query directly in SQL
        start_time = time.time()
        cursor.execute("SELECT * FROM mystical_spheres WHERE color='" + query + "'")
        rows = cursor.fetchall()
        
        # Simulated delay for time-based SQL injection
        # Easier to notice delays on zero results, simulate on no matches deliberately.
        if not rows:
            time.sleep(5)  # 5 seconds delay if no match

        response = "<div style='color: yellow; margin-top: 20px;'>"
        if rows:
            for row in rows:
                response += f"<div>{row[1]}: {row[2]}</div>"
        else:
            response += "No mystical sphere found for this color."
        response += "</div>"

    except Exception as e:
        response = f"<div style='color: red; margin-top: 20px;'>An error has occurred: {str(e)}</div>"

    finally:
        conn.close()

    return render_template_string(html_template + response)

if __name__ == '__main__':
    # Use this for deb)