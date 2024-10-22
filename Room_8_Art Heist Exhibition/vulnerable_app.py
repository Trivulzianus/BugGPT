from flask import Flask, request, render_template_string, redirect, url_for

app = Flask(__name__)

# Sample database of users and artwork
users = {
    "artlover": {"password": "colorfulcanvas", "owned_artwork_ids": [101]},
    "curator": {"password": "gallerymystery", "owned_artwork_ids": [102, 103]},
}

artworks = {
    101: {"title": "Dreamy Landscape", "artist": "Vivid Visionary", "desc": "A stunning landscape with vibrant hues."},
    102: {"title": "Abstract Enigma", "artist": "Mystical Master", "desc": "An abstract piece filled with enigmatic shapes."},
    103: {"title": "Silent Street", "artist": "Whispers of Gray", "desc": "A quiet street captured at twilight."}
}

@app.route('/')
def index():
    return '''
    <html>
    <head>
        <title>Art Heist Exhibition</title>
        <style>
            body {
                background-color: #f2f2f2;
                font-family: 'Trebuchet MS', sans-serif;
            }
            .container {
                width: 80%;
                margin: auto;
                overflow: hidden;
            }
            #main-header {
                color: #ffffff;
                background-color: #333333;
                padding-top: 30px;
                min-height: 70px;
                border-bottom: #e8491d 3px solid;
            }
            #main-header h1 {
                text-align: center;
                text-transform: uppercase;
                margin: 0;
                font-size: 24px;
            }
            .artwork {
                background-color: #ffffff;
                margin-top: 30px;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 0 10px rgba(0,0,0,0.1);
            }
            .artwork h2 {
                color: #e8491d;
            }
            .gallery {
                display: flex;
                justify-content: space-evenly;
            }
            .description {
                font-style: italic;
            }
        </style>
    </head>
    <body>
        <header id="main-header">
            <h1>Welcome to the Art Heist Exhibition</h1>
        </header>

        <div class="container">
            <form method="POST" action="/login">
                <input type="text" name="username" placeholder="Username" />
                <input type="password" name="password" placeholder="Password" />
                <input type="submit" value="Enter the Gallery" />
            </form>
            <div class="gallery">
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    user = users.get(username)

    if user and user['password'] == password:
        return redirect(url_for('gallery', user=username))
    else:
        return "Failed login attempt: The security guards are watching.", 403

@app.route('/gallery')
def gallery():
    username = request.args.get('user')
    user = users.get(username)
    
    if not user:
        return "You've wandered into a restricted area.", 403

    gallery_html = '''
    <div class="gallery">
    '''
    for art_id in user['owned_artwork_ids']:
        art = artworks.get(art_id)
        if art:
            gallery_html += f'''
            <div class="artwork">
                <h2>{art['title']}</h2>
                <p><strong>Artist: </strong>{art['artist']}</p>
                <p class="description">{art['desc']}</p>
                <a href="/art_details?id={art_id}">View Details</a>
            </div>
            '''

    gallery_html += '</div>'
    return render_template_string(gallery_html)

@app.route('/art_details')
def art_details():
    art_id = int(request.args.get('id'))
    art = artworks.get(art_id)

    if not art:
        return "The painting you seek has vanished.", 404

    art_html = f'''
    <html>
    <head>
        <title>Art Heist Exhibition - {art['title']}</title>
    </head>
    <body>
        <div class="artwork">
            <h2>{art['title']}</h2>
            <p><strong>Artist: </strong>{art['artist']}</p>
            <p class="description">{art['desc']}</p>
        </div>
        <a href="/">Back to Gallery</a>
    </body>
    </html>
    '''

    return render_template_string(art_html)

if __name__ == '__main__':
    app.run(debug=True)