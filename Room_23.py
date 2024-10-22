from flask import Flask, render_template_string, request

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():
    narrative = """
    <h1 style="text-align:center; color: #4CAF50;">Welcome to the Wonders of the Enchanted Forest</h1>
    <p style="color: #388E3C;">
        Journey deep into the heart of the Enchanted Forest, where witches brew their potions and mischievous spirits play games. 
        Among the whispering trees, an arcane challenge awaits the brave-hearted adventurers who dare to unravel the secrets hidden within.
    </p>
    <p style="color: #D32F2F;">
        However, beware! The Enchanted Forest is not as playful as it seems. Hidden within the shadows is a riddle so devious it tricked even 
        the most cunning sorcerers of the past. Your mission is to find the hidden treasure without triggering the curse it holds.
    </p>
    <p>
        Many have attempted, few have succeeded. Will you solve the mystery and obtain the secret that lies beneath?
    </p>
    <p style="text-align:center; color: #1976D2;">
        The key to success lies where the faeries meet. Solve the puzzle, whisper the right incantation, and glory shall be yours!
    </p>
    """

    if request.method == "POST":
        # Vulnerable input processing, unsafely displayed back to the user
        user_faerie_spell = request.form.get("faerie_spell", '')
        
        # This intentionally allows sanitized XSS for testing purposes
        sanitization = user_faerie_spell.replace("<", "&lt;").replace(">", "&gt;")

        response_html = f"""
        {narrative}
        <form method="post" style="text-align:center;">
            <input type="text" name="faerie_spell" style="margin-top:20px;" placeholder="Enter your faerie spell..." required/>
            <button type="submit" style="background-color:#FFC107; color:white; margin-top:10px;">Invoke Spell</button>
        </form>
        <div style="margin-top:40px; text-align:center; color: #FFC107;">Your Spell Echoed: {sanitization}</div>
        """
        return render_template_string(response_html)

    form_html = f"""
    {narrative}
    <form method="post" style="text-align:center;">
        <input type="text" name="faerie_spell" style="margin-top:20px;" placeholder="Enter your faerie spell..." required/>
        <button type="submit" style="background-color:#FFC107; color:white; margin-top:10px;">Invoke Spell</button>
    </form>
    """

    return render_template_string(form_html)

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)