from flask import Flask, request, render_template_string
import re

app = Flask(__name__)

# Simple in-memory "database" for demonstration purposes
user_submissions = []

@app.route('/', methods=['GET', 'POST'])
def index():
    message = ''
    if request.method == 'POST':
        # Capture user input
        user_input = request.form.get('comment', '')
        # Simple sanitization (which we'll intentionally bypass in the XSS challenge)
        sanitized_input = re.sub(r'[<>]', '', user_input)
        user_submissions.append(sanitized_input)
        message = 'Your comment has been submitted!'
    
    # HTML content with narrative and XSS vulnerability
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Escape the Enigma</title>
        <style>
            body {
                background: linear-gradient(135deg, #f06, pink);
                font-family: 'Arial', sans-serif;
                color: #fff;
                text-align: center;
                padding: 50px;
            }
            .container {
                background: rgba(0, 0, 0, 0.6);
                padding: 20px;
                border-radius: 10px;
                max-width: 800px;
                margin: auto;
            }
            input, textarea {
                width: 80%;
                padding: 10px;
                margin: 10px 0;
                border-radius: 5px;
                border: none;
            }
            button {
                padding: 10px 20px;
                border: none;
                border-radius: 5px;
                background-color: #ff4081;
                color: #fff;
                cursor: pointer;
                font-size: 16px;
            }
            .submissions {
                text-align: left;
                margin-top: 30px;
            }
            .submission {
                background: rgba(255, 255, 255, 0.1);
                padding: 10px;
                border-radius: 5px;
                margin-bottom: 10px;
                word-wrap: break-word;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Welcome to the Enchanted Portal</h1>
            <p>Embark on a journey where your wit and skill are your only allies. Share your thoughts, but beware—hidden within the shadows lies a challenge to your prowess.</p>
            
            <form method="POST" action="/">
                <textarea name="comment" rows="4" placeholder="Leave your mark..."></textarea><br>
                <button type="submit">Submit</button>
            </form>
            <p style="color: #0f0;">{{ message }}</p>
            
            <div class="submissions">
                <h2>Glowing Messages</h2>
                {% for submission in submissions %}
                    <div class="submission">{{ submission }}</div>
                {% endfor %}
            </div>
            
            <div id="easter-egg" style="display: none;">
                <h2>Congratulations!</h2>
                <p>You have uncovered the hidden message!</p>
            </div>
        </div>
        
        <script>
            // Hidden functionality that can be exploited via XSS
            document.addEventListener('DOMContentLoaded', function() {
                const submissions = {{ submissions|tojson }};
                submissions.forEach(function(msg) {
                    if(msg.includes('uncover')) {
                        document.getElementById('easter-egg').style.display = 'block';
                    }
                });
            });
        </script>
    </body>
    </html>
    """
    
    return render_template_string(html_content, submissions=user_submissions, message=message)

if __name__ == '__main__':
    app.run(debug=True)