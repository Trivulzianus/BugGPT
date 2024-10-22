a complex and challenging Flask application with an XXE vulnerability, here's the Python script for you. This application represents an art gallery where users can upload XML files to display their own art, but hidden within it is the opportunity to exploit an XXE vulnerability.

```python
from flask import Flask, request, render_template_string
import os

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def art_gallery():
    if request.method == 'POST':
        xml_content = request.files['file'].read()
        # Intentionally vulnerable to XXE
        art_description = parse_xml(xml_content)

        return render_template_string("""
        <html>
            <head>
                <style>
                    body {
                        background-color: #f0f0f0;
                        font-family: 'Comic Sans MS', 'Comic Sans', cursive;
                        text-align: center;
                        padding: 20px;
                    }
                    .art-frame {
                        border: 5px solid #8b8b8b;
                        background-color: white;
                        box-shadow: 5px 5px 15px #aaaaaa;
                        padding: 20px;
                        margin: 20px auto;
                        width: 60%;
                    }
                    h1 {
                        color: #333;
                    }
                    h2 {
                        color: #555;
                    }
                    .mystery {
                        color: #888;
                        font-style: italic;
                        padding: 10px;
                    }
                </style>
            </head>
            <body>
                <h1>Welcome to the Secret Art Gallery</h1>
                <div class="art-frame">
                    <h2>Your Art Description</h2>
                    <div class="mystery">
                        {{ art_description }}
                    </div>
                </div>
                <form method="post" enctype="multipart/form-data">
                    <input type="file" name="file"/>
                    <input type="submit" value="Submit Your Art"/>
                </form>
            </body>
        </html>
        """, art_description=art_description)

    return """
    <html>
        <head>
            <style>
                body {
                    background-color: #f0f0f0;
                    font-family: 'Comic Sans MS', 'Comic Sans', cursive;
                    text-align: center;
                    padding: 20px;
                }
                .gallery {
                    margin: 20px auto;
                    border: 5px solid #8b8b8b;
                    box-shadow: 5px 5px 15px #aaaaaa;
                    padding: 20px;
                    width: 60%;
                    background-color: white;
                }
                .title {
                    color: #333;
                }
                .narrative {
                    color: #555;
                    margin-top: 15px;
                }
            </style>
        </head>
        <body>
            <h1 class="title">Secret Art Gallery Upload Portal</h1>
            <div class="gallery">
                <p class="narrative">
                    Our gallery is an enigmatic display of untold secrets and hidden treasures. 
                    Submit your masterpiece in the form of an XML file and unravel the veiled stories within.
                </p>
                <form method="post" enctype="multipart/form-data">
                    <input type="file" name="file" required/>
                    <input type="submit" value="Submit Your Art"/>
                </form>
            </div>
        </body>
    </html>
    """

def parse_xml(xml_content):
    import xml.etree.ElementTree as ET
    # This is the area where the XXE vulnerability is introduced
    tree = ET.ElementTree(ET.fromstring(xml_content))
    root = tree.getroot()
    description = root.find('description')
    return description.text if description is not None else '[No description found]'

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
```

This web application allows users to upload an XML file containing art descriptions. The embedded XXE vulnerability inside the `parse_xml()` function will give users a challenge to exploit it. The webpage utilizes basic HTML and CSS for styling to make it visually compelling as an artistic puz