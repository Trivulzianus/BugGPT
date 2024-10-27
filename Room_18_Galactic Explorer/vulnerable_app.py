from flask import Flask, request, render_template_string, jsonify, redirect, url_for, abort

app = Flask(__name__)

# Sample data representing planets, only user_id 1 should have access to more detailed information
planet_data = {
    "1": {"name": "Xenon", "description": "A luminous gas giant with mysterious rings.", "secret": "Hidden Glowing Cave"},
    "2": {"name": "Aetheria", "description": "A planet covered in endless skies and floating islands."},
    "3": {"name": "Eldoria", "description": "A breathtaking world with vast meadows and ancient ruins."},
}

# Sample user data
user_data = {
    "1": {"username": "astro_learner", "can_view": ["1", "2"]},
    "2": {"username": "cosmic_seeker", "can_view": ["3"]},
}

def render_index_page():
    return render_template_string('''
    <html>
    <head>
        <title>Galactic Explorer</title>
        <style>
            body { font-family: Arial, sans-serif; background: linear-gradient(to right, #0f0c29, #302b63, #24243e); color: #fff; }
            h1 { color: #ffb400; }
            .planet { border: 2px solid #fff; margin: 20px; padding: 20px; border-radius: 10px; }
            footer { color: #0abab5; text-align: center; }
        </style>
    </head>
    <body>
        <h1>Welcome to Galactic Explorer</h1>
        <p>Dive into the vast universe and discover the secrets of each planet. But be wary, not all paths are yours to take.</p>

        <div class="planet">
            <h2>Xenon</h2>
            <p>A luminous gas giant with mysterious rings.</p>
            <a href="/planet/1">Explore the secrets of Xenon</a>
        </div>

        <div class="planet">
            <h2>Aetheria</h2>
            <p>A planet covered in endless skies and floating islands.</p>
            <a href="/planet/2">Explore the wonders of Aetheria</a>
        </div>

        <div class="planet">
            <h2>Eldoria</h2>
            <p>A breathtaking world with vast meadows and ancient ruins.</p>
            <a href="/planet/3">Discover the history of Eldoria</a>
        </div>

        <footer>Galactic Explorer 3023 © Cosmic Ventures</footer>
    </body>
    </html>
    ''')

@app.route('/')
def index():
    # Assume user_id is obtained through some authentication mechanism (simulated here for simplicity)
    # In the context of testing IDOR, we assume the user_id is "1"
    user_id = "1"
    return render_index_page()

@app.route('/planet/<planet_id>')
def planet(planet_id):
    user_id = "1"  # Simulating user_id

    if planet_id in user_data[user_id]['can_view']:
        planet_info = planet_data.get(planet_id)
        if planet_info is None:
            abort(404)
        
        # Returning secret detail if user has access
        explore = ''
        if user_id == "1" and planet_id == "1":
            explore = f"<p style='color: gold;'>Secret Discovery: {planet_info['secret']}</p>"
        
        return render_template_string(f'''
        <html>
        <head>
            <title>{planet_info['name']}</title>
            <style>
                body {{ font-family: Arial, sans-serif; background: #27272b; color: #c9c9c9; }}
                h1 {{ color: #36d6e7; }}
                footer {{ color: #0abab5; text-align: center; }}
            </style>
        </head>
        <body>
            <h1>{planet_info['name']}</h1>
            <p>{planet_info['description']}</p>
            {explore}
            <a href="/">Back to Galactic Explorer</a>
            <footer>Galactic Explorer 3023 © Cosmic Ventures</footer>
        </body>
        </html>
        ''')
    else:
        return abort(403)

if __name__ == "__main__":
    app.run(debug=True)