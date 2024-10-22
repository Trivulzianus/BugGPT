from flask import Flask, request, render_template_string
import random

app = Flask(__name__)

@app.route('/')
def index():
    # Narrative: Welcome to the "Chronicles of Flask: The Quest for the Lost Script". 
    # Your mission, should you choose to accept it, is to unearth the hidden vulnerabilities 
    # that lie within this seemingly harmless web page. The future of digital artifacts 
    # depends on you, brave cyber adventurer!

    narratives = [
        "Deep in the ancient Flask forests, where data whispers secrets of the past...",
        "As the digital sun sets over the mystical data lakes, shadows reveal vulnerabilities...",
        "In the cryptic realms of Cyberia, where only the brave dare to tread...",
        "Through the reflection of the code streams, truths await to be unveiled...",
    ]

    # Choose a random narrative for the page background story
    narrative = random.choice(narratives)

    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Chronicles of Flask</title>
        <style>
            body {
                background: linear-gradient(45deg, #ffccff 25%, #ccffff 75%);
                font-family: 'Courier New', Courier, monospace;
                padding: 20px;
                color: #333;
            }
            h1 {
                text-shadow: 2px 2px 5px #ff6666;
                color: #990099;
            }
            .narrative {
                font-style: italic;
                font-size: 1.2em;
            }
            #commentary {
                color: #004400;
                border: 1px dashed #004400;
                padding: 10px;
                background-color: #e6ffe6;
                margin-top: 20px;
            }
        </style>
    </head>
    <body>
        <h1>The Chronicles of Flask: The Quest for the Lost Script</h1>
        <div class="narrative">
            <p>{{ narrative }}</p>
        </div>
        <p>As the chosen one, you must test the fortifications of this digital sanctum. Tread carefully; the web is fraught with hidden dangers. Expect the unexpected!</p>
        <form action="#" method="get">
            <label for="userinput">Enter your analysis:</label>
            <input type="text" id="userinput" name="userinput" required>
            <button type="submit">Submit Insight</button>
        </form>
        <div id="commentary"></div>

        <script>
            // A vulnerable spot awaits, can you identify it?
            var userInput = new URLSearchParams(window.location.search).get('userinput');
            if (userInput) {
                // Directly injecting user input into HTML, a common pitfall
                document.getElementById('commentary').innerHTML = '<strong>Adventurer\'s Insight:</strong> ' + userInput;
            }
        </script>
    </body>
    </html>
    ''', narrative=narrative)

if __name__ == '__main__':
    app.run(debug=True)