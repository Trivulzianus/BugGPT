from flask import Flask, request, render_template_string

app = Flask(__name__)

# This is a sample art piece database
art_gallery = {
    "ART001": "The Starry Night by Vincent Van Gogh",
    "ART002": "The Persistence of Memory by Salvador Dalí",
    "ART003": "The Scream by Edvard Munch",
    "ART004": "Girl with a Pearl Earring by Johannes Vermeer",
}

# HTML Template with inline CSS and JavaScript
page_template = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Enigmatic Art Gallery</title>
<style>
    body { background: linear-gradient(120deg, #a6c0fe, #f68084); color: #333; font-family: 'Comic Sans MS', cursive, sans-serif; text-align: center; padding: 50px; }
    .header { font-size: 2.5em; margin-bottom: 20px; }
    .art { border: 2px solid #fff; padding: 10px; margin-top: 20px; background: rgba(255,255,255,0.2); }
    .narrative { font-size: 1.2em; margin-bottom: 30px; }
    .hint { color: #ffeb3b; }
</style>
</head>
<body>
    <div class="header">Welcome to the Enigmatic Art Gallery</div>
    <div class="narrative">
        As you step into this digital realm, each artwork awaits your discovery through their magical codes.
        Venture forth, search for an art piece, and unravel its story.
    </div>
    <form>
        <input type="text" id="artCode" name="artCode" placeholder="Enter Art Code" />
        <button type="button" onclick="findArt()">Find Art</button>
    </form>
    <div id="artDisplay" class="art"></div>

    <script>
        function findArt() {
            const code = document.getElementById("artCode").value;
            let displayArea = document.getElementById("artDisplay");
            if (code === "") {
                displayArea.innerHTML = "Please enter an art code.";
            } else {
                // Vulnerable code
                displayArea.innerHTML = "Fetching info for: " + decodeURIComponent(code);
                fetchInfoForArt(code);
            }
        }
        
        // This simulates a backend call to fetch art info
        function fetchInfoForArt(code) {
            const gallery = {
                "ART001": "The Starry Night by Vincent Van Gogh",
                "ART002": "The Persistence of Memory by Salvador Dalí",
                "ART003": "The Scream by Edvard Munch",
                "ART004": "Girl with a Pearl Earring by Johannes Vermeer"
            };
           
            let artInfo = gallery[code];
            if (artInfo) {
                document.getElementById("artDisplay").innerHTML += "<div>" + artInfo + "</div>";
            } else {
                document.getElementById("artDisplay").innerHTML += "<div class='hint'>The art piece is elusive, perhaps mishandled...</div>";
            }
        }
    </script>
</body>
</html>
"""

@app.route('/', methods=['GET'])
def index():
    user_input = request.args.get('artCode', '')
    return render_template_string(page_template, artCode=user_input)

if __name__ == '__main__':
    app.run(debug=True)