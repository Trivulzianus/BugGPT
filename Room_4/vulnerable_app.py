from flask import Flask, request, render_template_string
import requests

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    web_page_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Mystery Corporation: Internal Chronicles</title>
        <style>
            body {
                font-family: 'Courier New', Courier, monospace;
                background: linear-gradient(to right, #00c6ff, #0072ff);
                color: #fff;
                text-align: center;
                padding: 50px;
            }
            .container {
                max-width: 900px;
                margin: auto;
                background: rgba(255, 255, 255, 0.1);
                border-radius: 10px;
                padding: 20px;
            }
            input[type="text"] {
                padding: 10px;
                width: 50%;
                border-radius: 5px;
                border: none;
                margin-top: 20px;
            }
            button {
                padding: 10px 20px;
                border: none;
                border-radius: 5px;
                background-color: #0072ff;
                color: white;
                cursor: pointer;
            }
            button:hover {
                background-color: #005bb5;
            }
            .note {
                font-style: italic;
                color: #eaeaea;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>The Enigma at Visionary Tech Inc.</h1>
            <p>You are a top detective enlisted by Visionary Tech, a mysterious corporation with a hidden message in their internal endpoints. To solve this puzzle, you must uncover and access the right internal path.</p>
            <p>Enter an endpoint to begin your investigation:</p>
            <form method="POST">
                <input type="text" name="endpoint" required>
                <button type="submit">Probe</button>
            </form>
            <div>
                {% if message %}
                <p class="note">{{ message }}</p>
                {% endif %}
            </div>
        </div>
    </body>
    </html>
    """
    
    if request.method == 'POST':
        endpoint = request.form['endpoint']
        try:
            # Attempt to fetch data from user-specified endpoint
            response = requests.get(endpoint)
            message = "An unexpected information was found: {}".format(response.text[:250])  # Display only a snippet
        except Exception as e:
            message = str(e)
    else:
        message = None

    return render_template_string(web_page_template, message=message)

if __name__ == '__main__':
    app.run(debug=True)