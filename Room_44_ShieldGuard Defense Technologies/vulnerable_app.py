from flask import Flask, request, render_template_string
import re

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    feedback = ''
    if request.method == 'POST':
        user_input = request.form.get('feedback', '')
        # Highly sanitized input to prevent XSS attacks
        sanitized_input = re.sub(r'[<>]', '', user_input)  # Remove angle brackets
        feedback = sanitized_input  # This may still be vulnerable in certain contexts

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>ShieldGuard Defense Technologies</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #eef2f5; margin: 0; padding: 0; }
            .header { background-color: #002147; color: #ffffff; padding: 20px; text-align: center; }
            .nav { overflow: hidden; background-color: #333; }
            .nav a { float: left; display: block; color: #f2f2f2; text-align: center;
                     padding: 14px 16px; text-decoration: none; }
            .nav a:hover { background-color: #ddd; color: black; }
            .content { padding: 20px; }
            .footer { background-color: #002147; color: #ffffff; text-align: center; padding: 10px; position: fixed;
                      left: 0; bottom: 0; width: 100%; }
            .feedback { background-color: #f9f9f9; padding: 10px; margin-top: 20px; border-radius: 5px; }
            .feedback h2 { color: #002147; }
            .feedback p { font-style: italic; }
            form { margin-top: 20px; }
            input[type=text], textarea { width: 100%; padding: 12px; border: 1px solid #ccc; border-radius: 4px;
                                         resize: vertical; }
            input[type=submit] { background-color: #002147; color: white; padding: 12px 20px; border: none;
                                 border-radius: 4px; cursor: pointer; }
            input[type=submit]:hover { background-color: #435a78; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>ShieldGuard Defense Technologies</h1>
            <p>Innovating Tomorrow's Defense Solutions Today</p>
        </div>
        <div class="nav">
            <a href="#home">Home</a>
            <a href="#about">About Us</a>
            <a href="#solutions">Solutions</a>
            <a href="#contact">Contact</a>
        </div>
        <div class="content">
            <h2 id="about">About ShieldGuard</h2>
            <p>ShieldGuard Defense Technologies is a leading provider of advanced defense systems and solutions. With a commitment to innovation and excellence, we deliver unparalleled technology to secure the nation's interests.</p>
            <h2 id="solutions">Our Solutions</h2>
            <ul>
                <li>Cybersecurity Systems</li>
                <li>Aerospace and Avionics</li>
                <li>Autonomous Defense Robotics</li>
                <li>Advanced Surveillance Systems</li>
            </ul>
            <div class="feedback">
                <h2>Client Testimonials</h2>
                {% if feedback %}
                    <p>"{{ feedback }}"</p>
                {% else %}
                    <p>No testimonials yet. Be the first to leave your feedback!</p>
                {% endif %}
                <form method="post" action="/">
                    <label for="feedback">Leave Your Feedback:</label><br><br>
                    <textarea id="feedback" name="feedback" rows="4" placeholder="Your feedback..."></textarea><br><br>
                    <input type="submit" value="Submit Feedback">
                </form>
            </div>
        </div>
        <div class="footer">
            <p>&copy; 2023 ShieldGuard Defense Technologies. All rights reserved.</p>
        </div>
    </body>
    </html>
    """
    return render_template_string(html, feedback=feedback)

if __name__ == '__main__':
    app.run(debug=True)