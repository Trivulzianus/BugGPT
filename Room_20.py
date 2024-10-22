from flask import Flask, request, render_template_string
import random
import html

app = Flask(__name__)

@app.route('/')
def index():
    color_choices = ["red", "blue", "purple", "orange", "green"]
    random_color = random.choice(color_choices)

    narrative = """
    <div style="background-color: black; color: white; padding: 20px;">
        <h1 style="color: {}; text-align: center;">The Enchanted Forest of Web Security</h1>
        <p>Welcome, brave soul, to the Enchanted Forest where the spirits of the web roam freely. 
        Your quest is to uncover vulnerabilities hidden amongst the spectral trees. 
        Each apparition you encounter may be friendly—or it may hide a potential security threat.</p>
        <p>Your task today involves interacting with the ethereal Echo Sprite, a mischievous creature known to 
        repeat whatever it hears. Be careful, for the Echo Sprite has a mischievous streak and can reveal 
        secrets you did not intend!</p>
        <p style="font-size: 1.2em; color: yellow;">Will you prove yourself worthy by demonstrating your mastery over this web domain?</p>
    </div>
    """.format(random_color)

    user_input_form = """
    <div style="border: 2px dashed {}; margin: 20px; padding: 20px; background-color: #f9f9f9;">
        <h3>Speak to the Echo Sprite</h3>
        <form method="post" action="/echo">
            <label for="message">Your Message:</label><br>
            <input type="text" id="message" name="message" style="width: 50%; padding: 5px;"/><br>
            <input type="submit" value="Hear the Echo" style="margin-top: 10px;"/>
        </form>
    </div>
    """.format(random_color)

    return render_template_string(narrative + user_input_form)

@app.route('/echo', methods=['POST'])
def echo():
    message = request.form.get('message', '')
    sanitized_message = ''.join(c for c in message if c.isalnum() or c.isspace()) # Over-sanitization for challenge

    echo_response = """
    <div style="padding: 20px; border: 2px dotted {}; background-color: #e0e0e0;">
        <h3 style="color: {};">The Echo Sprite repeats:</h3>
        <p style="font-size: 1.5em; color: black;">{}</p>
        <p>Return to the <a href="/">Enchanted Forest</a> to continue your exploration.</p>
    </div>
    """.format(random_color, random_color, sanitized_message)

    return render_template_string(echo_response)

if __name__ == '__main__':
    app.run(debug=True)