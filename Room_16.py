from flask import Flask, request, render_template_string, escape
app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    # HTML template with a complex narrative for a mystical adventure challenge
    html_template = '''
    <html>
    <head>
        <title>The Enchanted Chronicles</title>
        <style>
            body { background-color: #1f1f2e; color: #f5f1e3; font-family: 'Courier New', monospace; }
            .container { width: 50%; margin: 0 auto; text-align: center; }
            h1 { color: #d4af37; }
            .mystical-text { color: #e07b39; }
            .input-box { border: none; padding: 10px; width: 80%; margin-top: 20px; }
            .submit-btn { background-color: #d4af37; color: #1f1f2e; padding: 10px; border: none; cursor: pointer; }
            .submit-btn:hover { background-color: #e07b39; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>The Enchanted Chronicles</h1>
            <p class="mystical-text">At the core of the Enchanted Forest lies a mystical portal guarded by ancient scripts... Only those who decipher its message can unveil its secrets.</p>
            <form method="post">
                <input class="input-box" type="text" name="mystical_input" placeholder="Type your incantation here..." />
                <button class="submit-btn" type="submit">Reveal</button>
            </form>
            {% if result %}
                <div>
                    <h2>Portal Message</h2>
                    <p>{{ result | safe }}</p> <!-- Simulating a potential XSS vector point -->
                </div>
            {% endif %}
        </div>
    </body>
    </html>
    '''
    
    result = None
    if request.method == 'POST':
        mystical_input = request.form.get('mystical_input', '')
        if 'portal' in mystical_input:  # Extremely sanitized input logic leading to an unanticipated bypass
            result = mystical_input  # Our challenge focal point with sanitized XSS vulnerability
        else:
            result = escape("The incantation failed. Try again, seeker of knowledge.")

    return render_template_string(html_template, result=result)

if __name__ == '__main__':
    app.run(debug=True)