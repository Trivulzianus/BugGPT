from flask import Flask, request, render_template_string
import requests

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    html_content = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>The Chronicles of NetQuest: The Enigma of the Whispering Server</title>
        <style>
            body {
                font-family: 'Arial', sans-serif;
                background: linear-gradient(135deg, #ff9a9e 0%, #fad0c4 99%, #fad0c4 100%);
                color: #555;
                text-align: center;
                padding: 50px;
            }
            h1 {
                font-size: 3em;
                color: #444;
            }
            p {
                font-size: 1.2em;
                margin-bottom: 30px;
            }
            .quest-container {
                background-color: rgba(255, 255, 255, 0.8);
                padding: 20px;
                border-radius: 10px;
                box-shadow: 0 10px 20px rgba(0, 0, 0, 0.2);
            }
            input[type="text"], input[type="submit"] {
                padding: 10px;
                font-size: 1em;
                margin: 10px 0;
            }
        </style>
    </head>
    <body>
        <div class="quest-container">
            <h1>The Chronicles of NetQuest</h1>
            <p>The Enigma of the Whispering Server awaits. Unveil its secrets, if you dare.</p>
            <form method="post">
                <input type="text" name="url" placeholder="Enter the sacred URL" size="50">
                <input type="submit" value="Summon the Whispers">
            </form>
            <div id="response">
                {% if response %}
                    <h2>The Whisperings:</h2>
                    <pre>{{ response }}</pre>
                {% endif %}
            </div>
        </div>
    </body>
    </html>
    '''
    
    response = None
    if request.method == 'POST':
        url = request.form.get('url')
        if url:
            try:
                # Intentionally vulnerable SSRF code
                response = requests.get(url).text
            except Exception as e:
                response = f"An error occurred: {e}"
    
    return render_template_string(html_content, response=response)

if __name__ == '__main__':
    app.run(debug=True)