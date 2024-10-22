from flask import Flask, request, render_template_string
import html

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    page_narrative = '''
    <html>
    <head>
        <title>The Enchanted Forest of Reflection</title>
        <style>
            body {
                background-color: #0D1F2D;
                color: #EAEAEA;
                font-family: 'Comic Sans MS', sans-serif;
                text-align: center;
            }
            h1 {
                color: #F2545B;
                font-size: 3em;
            }
            p {
                color: #F5CB5C;
                font-size: 1.2em;
            }
            .container {
                margin: 50px auto;
                padding: 20px;
                width: 70%;
                border: 2px solid #87A8A4;
                border-radius: 15px;
                background-color: #1E3D59;
            }
            input[type="text"] {
                padding: 10px;
                width: 80%;
                border-radius: 5px;
                border: 2px solid #F2545B;
            }
            input[type="submit"] {
                padding: 10px 20px;
                color: #FFF;
                border: none;
                border-radius: 5px;
                background-color: #F2545B;
                cursor: pointer;
            }
            input[type="submit"]:hover {
                background-color: #A80038;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>The Enchanted Forest of Reflection</h1>
            <p>
                You find yourself in the mystical Enchanted Forest, where echoes of your words turn into whispers of magic.
                Unearth the secrets by speaking your thoughts, but beware of the mirrored reflections that might reveal
                the hidden dark truths. Can you unveil the mysterious incantation hidden within?
            </p>
            <form method="POST">
                <input type="text" name="thought" placeholder="Speak your thoughts...">
                <input type="submit" value="Echo">
            </form>

            {% if reflection %}
                <div class="reflection">
                    <h2>Your Reflection:</h2>
                    <p>{{ reflection }}</p>
                </div>
            {% endif %}
        </div>
    </body>
    </html>
    '''

    reflection_raw = request.form.get('thought', '')

    # Here's where the reflected XSS vulnerability is intentionally introduced
    # by not escaping the user input when rendering it in the response.
    reflection = reflection_raw if reflection_raw else None

    return render_template_string(page_narrative, reflection=reflection)

if __name__ == '__main__':
    app.run(debug=True)