from flask import Flask, render_template_string, request

app = Flask(__name__)

@app.route('/')
def index():
    # HTML template with a deep lore and narrative embedded in the web page
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>The Enchanted Web of Eldoria</title>
        <style>
            body {
                background-color: #1a1a2e;
                color: #e6e6fa;
                font-family: 'Courier New', Courier, monospace;
                text-align: center;
            }
            .container {
                padding: 50px;
            }
            button {
                background-color: #e6e6fa;
                color: #1a1a2e;
                padding: 15px 32px;
                text-align: center;
                text-decoration: none;
                display: inline-block;
                font-size: 16px;
                margin: 4px 2px;
                cursor: pointer;
                border: none;
                border-radius: 12px;
            }
            .result {
                margin-top: 20px;
                font-size: 18px;
                color: #f5a623;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>The Enchanted Web of Eldoria</h1>
            <p>In the mystical realm of Eldoria, a story unfolds with every click...</p>
            <p>Only those who wield the power of JavaScript shall unveil the secrets hidden within.</p>
            <input id="wisdom" type="text" placeholder="Seek the ancient text..." />
            <button onclick="revealSecret()">Unlock the Lore</button>
            
            <div id="mystery" class="result"></div>
        </div>

        <script>
            function revealSecret() {
                var userInput = document.getElementById('wisdom').value;
                var saga = document.createElement('div');
                saga.innerHTML = decodeURIComponent(userInput);
                
                document.getElementById('mystery').appendChild(saga);
            }
        </script>
    </body>
    </html>
    """
    return render_template_string(html_content)

if __name__ == '__main__':
    app.run(debug=True)