from flask import Flask, request, render_template_string
import os

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    # Hidden narrative and styling for aesthetic appeal
    narrative = '''
    <style>
        body { font-family: 'Arial', sans-serif; background-color: #f3f4f6; }
        .container { max-width: 800px; margin: 50px auto; text-align: center; }
        h1 { color: #333; font-size: 3em; margin-bottom: 20px; }
        p { color: #666; line-height: 1.6; }
        pre { background: #eef; padding: 15px; text-align: left; }
        .disguised { display: none; }
    </style>
    <div class="container">
        <h1>The Enigma of the Oracles</h1>
        <p>
            You have stumbled upon the encrypted annals of an ancient oracle. Hidden within this intricate web 
            are secrets that only the most skilled can decrypt. The oracle speaks in a language of XML, but the truth 
            is veiled and persistently guarded. Unveil the transcripts and reveal the hidden wisdom.
        </p>
    '''

    # Base HTML form for XML input
    xml_input_form = '''
        <form method="post">
            <textarea name="xml_input" rows="10" cols="50" placeholder="Enter the Oracle's encrypted message..."></textarea><br><br>
            <input type="submit" value="Decrypt">
        </form>
    '''

    message = ''

    if request.method == 'POST':
        xml_input = request.form.get('xml_input')
        
        def secure_parse_xml(xml_str):
            if any(invalid in xml_str.lower() for invalid in ['<!doctype', '<!entity']):
                return "Suspicious content detected!"
            
            from xml.etree import ElementTree
            try:
                root = ElementTree.fromstring(xml_str)
                return ElementTree.tostring(root, encoding='unicode')
            except Exception as e:
                return f"An error occurred: {e}"

        message = secure_parse_xml(xml_input)

    body = narrative + xml_input_form + f'<pre>{message}</pre></div>'
    return render_template_string(body)

if __name__ == '__main__':
    app.run(debug=True)