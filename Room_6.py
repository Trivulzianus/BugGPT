from flask import Flask, request, render_template_string
import random

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    narrative = """
    <html>
    <head>
        <title>Colorful City Chronicles</title>
        <style>
            body { background-color: #f0f8ff; font-family: 'Courier New', monospace; color: #333; }
            .container { max-width: 800px; margin: 0 auto; padding: 20px; background-color: #fff; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
            h1 { color: #4CAF50; }
            p.story { font-size: 16px; line-height: 1.6; text-align: justify; }
            .notice { font-weight: bold; color: #d32f2f; }
            #result { margin-top: 20px; padding: 10px; border: 1px solid #eee; border-radius: 5px; background-color: #e1f0f8; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>The Colorful City Chronicles: A Mysterious Narrative</h1>
            <p class="story">In a whimsical city, colors paint stories untold, hues weaving tales in every alley and lamp post that echoes a tune. As you wander, the enigmatic streets whisper secrets of yore, waiting to be unveiled by those with a discerning eye.</p>

            <p class="notice">Remark: Despite the city's charm, there lurks an "Excessive Scripting Specter" that challenges only the bravest to discover and disarm its arcane code.</p>

            <form method="POST">
                <label for="input">Reveal the City's Mysteries:<br></label>
                <input type="text" id="input" name="user_input" style="width: 60%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                <input type="submit" value="Decode" style="padding: 8px 16px; border: none; background-color: #4CAF50; color: #fff; border-radius: 4px; cursor: pointer;">
            </form>

            {% if user_input %}
                <div id="result">{{ result|safe }}</div>
            {% endif %}
        </div>
    </body>
    </html>
    """

    user_input = ''
    result = ''
    if request.method == 'POST':
        user_input = request.form.get('user_input', '')
        # Introducing a potential XSS vulnerability for testing purposes
        result = f"A kaleidoscope of revelation unveils: {user_input}"

    return render_template_string(narrative, user_input=user_input, result=result)

if __name__ == '__main__':
    app.run(debug=True)
