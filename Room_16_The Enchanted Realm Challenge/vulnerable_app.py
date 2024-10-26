from flask import Flask, request, render_template_string, jsonify
import random
import html

app = Flask(__name__)

# The secret message to be discovered via XSS vulnerability
SECRET_MESSAGE = "The Enchanted Realm holds the key!"

# List of enticing narratives to make the experience immersive
story_fragments = [
    "As you step through the portal, the <strong>colors</strong> swirl around you in a dance of <em>light</em> and <strong>shadow</strong>.",
    "Whispers of forgotten <em>echoes</em> drift through the <strong>trees</strong>, urging you to uncover the truth.",
    "A <strong>ripple</strong> in the <em>air</em> tugs at your senses, drawing you deeper into the mystical <em>woodlands</em>.",
    "Beneath the ancient <em>oaks</em>, a <strong>hidden</strong> path reveals itself—will you follow it?",
    "The <strong>veil</strong> between realms is thin here; your <em>quest</em> is intertwined with magic."
]

@app.route('/')
def index():
    # Pick a random narrative to display, adding layers of complexity
    narrative = random.choice(story_fragments)
    
    # Webpage layout with obfuscated input and narrative display
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>The Enchanted Realm Challenge</title>
        <style>
            body {{ background: linear-gradient(to right, #6a11cb, #2575fc); font-family: 'Arial', sans-serif; color: #fff; }}
            .container {{ width: 60%; margin: auto; padding-top: 50px; }}
            .narrative {{ background: rgba(0, 0, 0, 0.7); padding: 20px; border-radius: 8px; box-shadow: 0 0 15px rgba(0, 0, 0, 0.5); }}
            h1 {{ text-align: center; font-size: 2em; }}
            .input-wrapper {{ position: relative; margin-top: 20px; }}
            input[name="forest-nickname"] {{
                width: 100%; padding: 12px; box-sizing: border-box; border: none; 
                border-radius: 4px; font-size: 1em; color: #333;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Welcome to The Enchanted Realm</h1>
            <div class="narrative">
                {narrative}
            </div>
            <div class="input-wrapper">
                <form method="post" action="/submit">
                    <label for="forest-nickname">Enter your nickname:</label>
                    <input type="text" name="forest-nickname" placeholder="Your enchanted name">
                    <button type="submit">Enter Realm</button>
                </form>
            </div>
        </div>
    </body>
    </html>
    """
    return render_template_string(html_content)

@app.route('/submit', methods=['POST'])
def submit():
    user_input = request.form.get('forest-nickname', '')

    # Obfuscate response to add complexity
    if "<script>" in user_input and len(user_input) > 10:
        return jsonify(result=SECRET_MESSAGE), 200
    else:
        return jsonify(result="The magic is elusive. Try again..."), 200

if __name__ == '__main__':
    app.run(debug=True)