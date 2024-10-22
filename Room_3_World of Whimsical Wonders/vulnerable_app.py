from flask import Flask, request, render_template_string, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'supersecretkey'

users = {
    'alice': {'password': generate_password_hash('wonderland'), 'message': 'Alice welcomes you to Wonderland!'},
    'bob': {'password': generate_password_hash('builder'), 'message': 'Bob is busy building his dreams!'},
    'carol': {'password': generate_password_hash('treasure'), 'message': 'Carol found a hidden treasure!'}
}

@app.route('/')
def index():
    session.clear()
    return render_template_string('''
    <html>
    <head>
        <title>World of Whimsical Wonders</title>
        <style>
            body { 
                background: linear-gradient(to right, #ffecd2 0%, #fcb69f 100%);
                font-family: 'Comic Sans MS', cursive, sans-serif;
                color: #383838;
                text-align: center;
                margin: 0;
                padding: 0;
            }
            .container {
                padding: 50px;
            }
            h1 {
                font-size: 3em;
            }
            .hint {
                color: #f05a28;
            }
            form {
                margin-top: 20px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>World of Whimsical Wonders</h1>
            <p>Welcome, brave adventurer, to the mystifying realm of the Whimsical Wonders!</p>
            <p class="hint">Choose your character to embark on a journey full of secrets!</p>
            <form method="post" action="{{ url_for('login') }}">
                <input type="text" name="username" placeholder="Character Name" required><br>
                <input type="password" name="password" placeholder="Secret Phrase" required><br>
                <button type="submit">Enter the Realm</button>
            </form>
        </div>
    </body>
    </html>
    ''')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    user = users.get(username)
    if user and check_password_hash(user['password'], password):
        session['user'] = username
        return redirect(url_for('profile', username=username))
    return 'The realms reject your entry. Wrong credentials.'

@app.route('/character/<username>')
def profile(username):
    if 'user' not in session:
        return 'You must log in to continue your adventure!'
    
    # IDOR Vulnerability: Users can access other profiles by manipulating this URI
    user = users.get(username)
    if user:
        return render_template_string(f'''
        <html>
        <head>
            <title>{username}'s Realm</title>
            <style>
                body {{
                    background: linear-gradient(to left, #8e2de2, #4a00e0);
                    font-family: 'Comic Sans MS', cursive, sans-serif;
                    color: #f0f0f0;
                    text-align: center;
                    margin: 0;
                    padding: 0;
                }}
                .container {{
                    padding: 50px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Welcome to {username}'s Realm!</h1>
                <p>{user['message']}</p>
                <a href="/">Return to Whimsical World</a>
            </div>
        </body>
        </html>
        ''')
    return 'The mists have obscured this path. Character not found.'

if __name__ == '__main__':
    app.run(debug=True)