from flask import Flask, request, render_template_string
import requests

app = Flask(__name__)

# HTML template with engaging narrative
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cosmic Quest: The Astral Codex</title>
    <style>
        body {
            background-color: #121212;
            color: #e0f7fa;
            font-family: 'Courier New', Courier, monospace;
        }
        header, footer {
            text-align: center;
            padding: 2em;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            text-align: center;
        }
        .starlit-button {
            display: inline-block;
            padding: 10px 20px;
            margin-top: 20px;
            font-size: 1.2em;
            background: linear-gradient(45deg, #ff9ff3, #feca57);
            border: none;
            border-radius: 7px;
            color: #121212;
            cursor: pointer;
        }
        .starlit-button:hover {
            box-shadow: 0px 0px 15px 3px rgba(255, 255, 255, 0.7);
        }
        textarea {
            width: 100%;
            height: 100px;
            margin-top: 10px;
            background-color: #333;
            color: #e0f7fa;
            border: 1px solid #feca57;
            border-radius: 5px;
            padding: 10px;
        }
    </style>
</head>
<body>
    <header>
        <h1>Cosmic Quest: The Astral Codex</h1>
    </header>
    <main class="container">
        <article>
            <p>Welcome, Seeker of the Stars. The Astral Codex, a legendary tome said to contain the secrets of the cosmos, has been encrypted within the celestial servers of the Orion Network. Your mission, should you choose to accept, is to traverse the digital galaxy, bypassing security constellations to retrieve the codex's sacred text. Beware, for only those with a profound understanding of cosmic interactions shall prevail.</p>
            <p>Initiate your journey by entering the coordinates of the star you wish to explore. Many have tried, but few have grasped the wisdom of the stars. The path lies within your hands.</p>
        </article>
        <form method="post">
            <textarea name="url" placeholder="Star Coordinates (URL)"></textarea>
            <button type="submit" class="starlit-button">Venture Forward</button>
        </form>
    </main>
    <footer>
        <p>Embark on the quest and join the cosmic savants in the hall of stars.</p>
    </footer>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        # Retrieve the URL entered by the user
        entered_url = request.form.get('url')

        try:
            # This is where SSRF vulnerability comes into play
            # An external request is made based on user input without validation
            response = requests.get(entered_url)
            result = f"Retrieved astral data: {response.text}"
        except Exception as e:
            result = f"An error occurred on your quest: {str(e)}"
        
        return render_template_string(HTML_TEMPLATE + "<div class='container'><p>" + result + "</p></div>")

    return render_template_string(HTML_TEMPLATE)

if __name__ == "__main__":
    app.run(debug=True)