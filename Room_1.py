from flask import Flask, request, render_template_string, make_response
import os

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    narrative = """
    <h1 style="color: #4CAF50;">The Mystical Library</h1>
    <p style="font-size: 18px;">Welcome, brave adventurer. You have entered the Mystical Library, a place where knowledge is both a gift and a curse. 
    Your objective is to unlock the secrets hidden within the Tome of Legends. But beware, not all paths are as they seem.</p>
    <p>In the center of the library lies the enigmatic tome. Some say it speaks, others say it listens. Your challenge is to discover the message it holds.</p>
    """
    
    form = """
    <form method="post">
        <label for="xmlInput" style="color: #FF5733;">Ask the Tome of Legends (Provide XML Input):</label><br /><br />
        <textarea id="xmlInput" name="xmlInput" rows="10" cols="30" style="font-family: 'Courier New';"></textarea><br /><br />
        <input type="submit" value="Consult the Tome" style="background-color: #5DADE2; color: white;"/>
    </form>
    """
    
    if request.method == 'POST':
        xml_input = request.form.get('xmlInput')
        if xml_input:
            try:
                response = parse_xml(xml_input)
                return render_template_string(narrative + form + f"<p style='color: #C70039;'>Tome whispers: {response}</p>")
            except Exception as e:
                return render_template_string(narrative + form + f"<p style='color: red;'>The Tome resists: {str(e)}</p>")
        
    return render_template_string(narrative + form)

def parse_xml(xml_content):
    import xml.etree.ElementTree as ET
    from xml.etree.ElementTree import TreeBuilder

    # Disable DOCTYPE processing (to make it a bit harder). However, this implementation is vulnerable.
    class NoDoctypeTreeBuilder(TreeBuilder):
        def doctype(self, name, pubid, system):
            pass

    parser = ET.XMLParser(target=NoDoctypeTreeBuilder())
    root = ET.fromstring(xml_content, parser=parser)
    
    result = ""
    for elem in root.iter():
        result += elem.tag + ": " + (elem.text if elem.text else "") + " | "
    
    # Vulnerable to XXE attack through file retrieval
    return result

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
