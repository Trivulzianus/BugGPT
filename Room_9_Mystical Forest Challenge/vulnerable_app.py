from flask import Flask, render_template_string, request, escape

app = Flask(__name__)

# HTML template for the web page
# The web page will have a "mystical forest" theme for the narrative
html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mystical Forest Challenge</title>
    <style>
        body {
            font-family: 'Arial', sans-serif;
            background-color: #f0f8ff;
            color: #333;
            text-align: center;
            padding: 30px;
        }
        h1 {
            color: #2e8b57;
        }
        #forest {
            background-image: url('https://example.com/forest.jpg'); /* Replace with a valid image URL */
            height: 250px;
            margin: 20px auto;
            border: 2px solid #8b4513;
        }
        input[type="text"], input[type="submit"] {
            padding: 10px;
            width: 80%;
            margin: 5px;
            border: 2px solid #2e8b57;
            border-radius: 5px;
        }
        #message {
            background-color: #fff8dc;
            padding: 20px;
            border: 2px solid #ffd700;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <h1>Mystical Forest Enigma</h1>
    <p>Welcome, seeker of wisdom. To pass through the mystical forest, you must solve the enigma. Enter the secret phrase to light your path.</p>
    <div id="forest"></div>
    <form method="POST" action="/">
        <input type="text" name="entry" placeholder="Enter the secret phrase" autocomplete="off">
        <input type="submit" value="Unlock the Mystery">
    </form>
    <div id="message">{message}</div>
    <script>
        // Add mysterious animations or effects
        document.addEventListener('DOMContentLoaded', function() {
            let forest = document.getElementById('forest');
            forest.style.transition = "all 1s";
            forest.addEventListener('mouseover', function() {
                this.style.transform = "scale(1.1)";
            });
            forest.addEventListener('mouseout', function() {
                this.style.transform = "scale(1)";
            });
        });
    </script>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def index():
    message = ""
    if request.method == "POST":
        # Vulnerable point with attempt to sanitize
        # Using escape function but not completely secure here
        user_input = request.form.get('entry', '')
        sanitized_input = escape(user_input)  # Attempt to escape HTML entities
        
        # A magical ceremony (flawed logic for a skilled eye)
        if "<script>" in user_input:
            message = f"Curious choice, adventurer: {sanitized_input}"
        elif "forest" in sanitized_input.lower():
            message = "The path unfolds before you, brave explorer."
        else:
            message = "The forest remains shrouded in mystery."

    return render_template_string(html_template, message=message)


if __name__ == "__main__":
    app.run(debug=True)