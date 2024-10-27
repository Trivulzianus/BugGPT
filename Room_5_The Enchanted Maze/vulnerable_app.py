from flask import Flask, render_template_string, request, redirect
import requests
import base64

app = Flask(__name__)

@app.route('/')
def home():
    return '''
    <html>
    <head>
        <title>The Enchanted Maze</title>
        <style>
            body { background-color: #f0e6f6; color: #4b0082; text-align: center; font-family: "Trebuchet MS", sans-serif; }
            h1 { color: #8a2be2; }
            p { font-size: 18px; }
            a { color: #9400d3; text-decoration: none; font-weight: bold; }
            a:hover { color: #ba55d3; }
            .button {
                background-color: #8a2be2;
                border: none;
                color: white;
                padding: 10px 24px;
                text-align: center;
                text-decoration: none;
                display: inline-block;
                font-size: 16px;
                margin: 10px 2px;
                cursor: pointer;
                border-radius: 16px;
            }
            .button:hover {
                background-color: #7b68ee;
            }
        </style>
    </head>
    <body>
        <h1>Welcome to the Enchanted Maze!</h1>
        <p>Brave adventurer, the mystical Maze awaits you. Legends say that those who reach the center will find untold treasures.</p>
        <a href="/enter" class="button">Enter the Maze</a>
    </body>
    </html>
    '''

@app.route('/enter')
def enter():
    return '''
    <html>
    <head>
        <title>The Maze Entrance</title>
        <style>
            body { background-color: #e6ffe6; color: #006400; text-align: center; font-family: "Trebuchet MS", sans-serif; }
            h1 { color: #228b22; }
            p { font-size: 18px; }
            select, input[type=submit] {
                padding: 10px;
                margin: 10px;
                font-size: 16px;
            }
            .link {
                color: #006400;
                text-decoration: none;
                font-weight: bold;
            }
            .link:hover {
                color: #32cd32;
            }
        </style>
    </head>
    <body>
        <h1>The Maze Entrance</h1>
        <p>Choose a path encoded in ancient runes (Base64) to proceed:</p>
        <form action="/navigate" method="get">
            <label for="path">Encoded Path:</label>
            <input type="text" id="path" name="path" value="b3B0aW9uMQ==" required>
            <br>
            <input type="submit" value="Navigate">
        </form>
        <p>Examples of encoded paths:</p>
        <ul style="list-style-type:none;">
            <li>Option 1: b3B0aW9uMQ==</li>
            <li>Option 2: b3B0aW9uMg==</li>
            <li>Option 3: b3B0aW9uMw==</li>
        </ul>
        <a href="/" class="link">Return to safety</a>
    </body>
    </html>
    '''

@app.route('/navigate')
def navigate():
    encoded_path = request.args.get('path', '')
    if not encoded_path:
        return redirect('/enter')
    try:
        # Decode the Base64 encoded path
        path = base64.b64decode(encoded_path).decode('utf-8')
    except Exception as e:
        return '''
        <html>
        <head>
            <title>Error</title>
            <style>
                body { background-color: #ffe6e6; color: #8b0000; text-align: center; font-family: "Trebuchet MS", sans-serif; }
                h1 { color: #b22222; }
                a { color: #8b0000; text-decoration: none; font-weight: bold; }
                a:hover { color: #dc143c; }
            </style>
        </head>
        <body>
            <h1>Invalid Path!</h1>
            <p>The ancient runes are unreadable. Please try again.</p>
            <a href="/enter">Back to Entrance</a>
        </body>
        </html>
        '''

    # Construct the URL without proper validation
    # This is intentionally vulnerable to SSRF attacks
    url = f"http://maze.server.internal/{path}"

    try:
        # The server requests the constructed URL
        r = requests.get(url, timeout=5)
        content = r.text
    except Exception as e:
        content = "The path leads to a dead end. There is nothing here."

    return render_template_string('''
    <html>
    <head>
        <title>Maze Path</title>
        <style>
            body { background-color: #f5f5dc; color: #8b4513; text-align: center; font-family: "Trebuchet MS", sans-serif; }
            h1 { color: #a0522d; }
            p { font-size: 18px; }
            a { color: #8b4513; text-decoration: none; font-weight: bold; }
            a:hover { color: #cd853f; }
            .content { 
                background-color: #fffaf0; 
                padding: 20px; 
                border: 2px solid #deb887; 
                border-radius: 10px; 
                display: inline-block;
                max-width: 80%;
                margin: 20px auto;
                word-wrap: break-word;
            }
        </style>
    </head>
    <body>
        <h1>The Result of Your Journey</h1>
        <div class="content">{{ content }}</div>
        <a href="/enter">Choose Another Path</a>
    </body>
    </html>
    ''', content=content)

if __name__ == '__main__':
    app.run(debug=True)