from flask import Flask, request, render_template_string
import requests

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    narrative_text = """
    <h1 style="color: #3498db;">The Enchanted Map</h1>
    <p style="color: #2ecc71;">In the mystical land of Cyberia, you stumble upon an ancient, enchanted map. This map is said to point to the location of the legendary Perl of the Protocol. However, the map is guarded by an ancient sorcery that only a skilled web practitioner can overcome. Each location on the map represents a portal you must successfully navigate using your web wizardry skills.</p>

    <p style="color: #e74c3c;">One of these portals uses a curious mechanism known as the 'Request Mirror', where you must unlock the next step by interacting with the portal in a very specific way.</p>

    <p style="color: #9b59b6;">Dare you test your skills and unlock the secrets of the Enchanted Map?</p>
    """
    
    form = """
    <h2 style="color: #f1c40f;">Portal Interaction Terminal</h2>
    <form method="post" style="background: #ecf0f1; padding: 20px; border-radius: 8px;">
        <label for="url" style="color: #2ecc71;">Enter a map endpoint:</label><br>
        <input type="text" id="url" name="url" style="width: 100%; padding: 12px; border-radius: 4px;" required><br><br>
        <input type="submit" value="Explore" style="background: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 4px;">
    </form>
    """
    
    if request.method == 'POST':
        url = request.form.get('url')
        try:
            # Simulate endpoint discovery (Note: this is a contrived example of an SSRF vulnerability)
            response = requests.get(url, timeout=3)
            return render_template_string(narrative_text + form + "<p>Response from your exploration:</p>" +
                                          f"<pre style='background: #d5d8dc; padding: 10px; border-radius: 5px;'>{response.text}</pre>")
        except requests.exceptions.RequestException as e:
            return render_template_string(narrative_text + form + "<p style='color: #e74c3c;'>The portal remains sealed. Try another path.</p>")

    return render_template_string(narrative_text + form)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
