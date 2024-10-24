from flask import Flask, render_template_string, request

app = Flask(__name__)

@app.route('/')
def index():
    # Complex and engaging narrative
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>The Mirror of Aether: A DOM XSS Challenge</title>
        <style>
            body {
                background: linear-gradient(145deg, #4e54c8, #8f94fb);
                color: #fff;
                font-family: 'Arial', sans-serif;
                margin: 0;
                padding: 0;
                overflow-x: hidden;
            }
            .container {
                text-align: center;
                padding: 50px;
            }
            h1 {
                font-size: 3em;
                margin-bottom: 0.5em;
            }
            p {
                font-size: 1.2em;
            }
            #quest {
                display: inline-block;
                margin-top: 30px;
                padding: 10px 20px;
                border: 2px solid #fff;
                border-radius: 5px;
                background-color: rgba(255, 255, 255, 0.1);
                color: #fff;
                cursor: pointer;
                transition: all 0.3s ease;
            }
            #quest:hover {
                background-color: rgba(255, 255, 255, 0.3);
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>The Mirror of Aether</h1>
            <p>You have entered the realm of the Web Sorcerer, where the Aetherial Mirror stores the tales of countless souls. Your task is to uncover the hidden truths ensnared within the mysterious scripts of the Mirror. Use your wisdom to unveil the secrets hidden in the reflections.</p>

            <div id="challenge">
                <!-- Narrative-driven DOM element to attach scripts -->
                <p>Enter your <em>rune</em> to reflect upon the Aether:</p>
                <input type="text" id="rune" />
                <div id="quest">Reveal the Reflection</div>
            </div>

            <script>
                // Intricately designed script for DOM-based XSS
                let questButton = document.getElementById('quest');
                let runeInput = document.getElementById('rune');

                questButton.addEventListener('click', function() {
                    let rune = runeInput.value;
                    if (rune) {
                        // Dangerous insertion point, where user input is improperly handled
                        let reflection = "<div>The Aether reflects the rune: " + rune + "</div>";
                        document.body.insertAdjacentHTML('beforeend', reflection);
                    }
                });
            </script>
        </div>
    </body>
    </html>
    """
    return render_template_string(html_content)

if __name__ == '__main__':
    app.run(debug=True)