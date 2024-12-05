from flask import Flask, render_template_string, request
import re

app = Flask(__name__)

def sanitize_input(user_input):
    """
    A flawed sanitization function that attempts to remove <script> tags.
    Due to improper regex, it can be bypassed with crafted inputs.
    """
    # Attempt to remove script tags using regex
    sanitized = re.sub(r'<\s*script[^>]*>(.*?)<\s*/\s*script>', '', user_input, flags=re.IGNORECASE)
    return sanitized

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        feedback = request.form.get('feedback', '')
        sanitized_feedback = sanitize_input(feedback)
        return render_template_string(template, feedback=sanitized_feedback)
    else:
        return render_template_string(template, feedback=None)

# The HTML template as a multi-line string
template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Harmony University - Empowering Minds</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; }
        .header { background-color: #4A90E2; color: white; padding: 20px; text-align: center; }
        .nav { overflow: hidden; background-color: #333; }
        .nav a { float: left; display: block; color: #f2f2f2; text-align: center; 
                 padding: 14px 16px; text-decoration: none; }
        .nav a:hover { background-color: #ddd; color: black; }
        .banner { background-image: url('https://www.example.com/banner.jpg'); 
                  background-size: cover; padding: 100px; text-align: center; color: white; }
        .content { padding: 20px; }
        .footer { background-color: #333; color: white; padding: 10px; text-align: center; }
        .feedback-form { background-color: #f9f9f9; padding: 20px; margin-top: 20px; border-radius: 5px; }
        .feedback-form textarea { width: 100%; resize: none; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Harmony University</h1>
        <p>"Where Innovation Meets Excellence"</p>
    </div>
    <div class="nav">
        <a href="#">Home</a>
        <a href="#">Admissions</a>
        <a href="#">Programs</a>
        <a href="#">Research</a>
        <a href="#">Contact Us</a>
    </div>
    <div class="banner">
        <h2>Welcome to Harmony University</h2>
        <p>Shaping the future, one mind at a time.</p>
    </div>
    <div class="content">
        <h2>About Us</h2>
        <p>Harmony University is a premier institution committed to excellence in teaching, learning, and research.
           We foster a diverse and inclusive environment where students can thrive and achieve their full potential.</p>
        <h3>Student Feedback</h3>
        <p>We value your feedback. Please share your thoughts with us below:</p>
        <div class="feedback-form">
            <form method="post" action="/">
                <textarea name="feedback" rows="5" placeholder="Enter your feedback here..."></textarea><br><br>
                <input type="submit" value="Submit Feedback">
            </form>
            {% if feedback %}
            <h4>Your Feedback:</h4>
            <p>{{ feedback|safe }}</p>
            {% endif %}
        </div>
    </div>
    <div class="footer">
        <p>&copy; 2023 Harmony University. All rights reserved.</p>
    </div>
</body>
</html>
'''

if __name__ == '__main__':
    app.run(debug=True)