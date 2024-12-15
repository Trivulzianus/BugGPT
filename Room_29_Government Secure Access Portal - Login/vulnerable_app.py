from flask import Flask, render_template_string, request, redirect, url_for, session
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'

def init_db():
    if not os.path.exists('database.db'):
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                fullname TEXT NOT NULL
            )
        ''')
        c.execute('''
            CREATE TABLE documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        # Insert sample users
        c.execute("INSERT INTO users (username, password, fullname) VALUES (?, ?, ?)", ('alice', 'password123', 'Alice Smith'))
        c.execute("INSERT INTO users (username, password, fullname) VALUES (?, ?, ?)", ('bob', 'secret456', 'Bob Johnson'))
        # Insert sample documents
        c.execute("INSERT INTO documents (user_id, title, content) VALUES (?, ?, ?)", (1, 'Top Secret Document A', 'Content of Document A for Alice'))
        c.execute("INSERT INTO documents (user_id, title, content) VALUES (?, ?, ?)", (2, 'Confidential Report B', 'Content of Report B for Bob'))
        conn.commit()
        conn.close()

@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        # Process login
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT id, fullname FROM users WHERE username=? AND password=?', (username, password))
        user = c.fetchone()
        conn.close()
        if user:
            # Successful login
            session['user_id'] = user[0]
            session['fullname'] = user[1]
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid username or password'
    # Render login template
    template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Government Secure Access Portal - Login</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #eef2f7; }
            .container { width: 400px; margin: 100px auto; background-color: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); }
            h1 { text-align: center; color: #333; }
            .error { color: red; }
            input[type="text"], input[type="password"] { width: 100%; padding: 12px; margin: 8px 0; box-sizing: border-box; }
            input[type="submit"] { width: 100%; padding: 12px; background-color: #007BFF; color: white; border: none; cursor: pointer; }
            input[type="submit"]:hover { background-color: #0056b3; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Government Secure Access Portal</h1>
            {% if error %}
            <p class="error">{{ error }}</p>
            {% endif %}
            <form method="post">
                <input type="text" name="username" placeholder="Username" required /><br/>
                <input type="password" name="password" placeholder="Password" required /><br/>
                <input type="submit" value="Login" />
            </form>
        </div>
    </body>
    </html>
    '''
    return render_template_string(template, error=error)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT id, title FROM documents WHERE user_id=?', (user_id,))
    documents = c.fetchall()
    conn.close()
    # Generate access codes
    documents_with_access_codes = []
    for doc in documents:
        doc_id = doc[0]
        access_code = (doc_id * 12345) % 100000  # Simplistic access code
        documents_with_access_codes.append((doc_id, doc[1], access_code))
    # Render dashboard
    template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Government Secure Access Portal - Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #eef2f7; }
            .container { width: 700px; margin: 50px auto; background-color: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); }
            h1 { text-align: center; color: #333; }
            h2 { color: #333; }
            ul { list-style-type: none; padding: 0; }
            li { margin: 15px 0; }
            a { text-decoration: none; color: #007BFF; font-size: 18px; }
            a:hover { text-decoration: underline; }
            .logout { margin-top: 30px; text-align: center; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Welcome, {{ session.fullname }}</h1>
            <h2>Your Documents</h2>
            <ul>
                {% for doc in documents %}
                <li><a href="{{ url_for('view_document', doc_id=doc[0], access_code=doc[2]) }}">{{ doc[1] }}</a></li>
                {% endfor %}
            </ul>
            <div class="logout">
                <p><a href="{{ url_for('logout') }}">Logout</a></p>
            </div>
        </div>
    </body>
    </html>
    '''
    return render_template_string(template, documents=documents_with_access_codes)

@app.route('/document/<int:doc_id>')
def view_document(doc_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    access_code = request.args.get('access_code', '')
    if not access_code:
        return 'Access code missing', 403
    try:
        access_code = int(access_code)
    except ValueError:
        return 'Invalid access code', 403
    expected_access_code = (doc_id * 12345) % 100000
    if access_code != expected_access_code:
        return 'Invalid access code', 403
    # Load document
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT user_id, title, content FROM documents WHERE id=?', (doc_id,))
    doc = c.fetchone()
    conn.close()
    if doc:
        # Vulnerability: No ownership check; access is granted based on access_code only
        template = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>{{ doc[1] }} - Government Secure Access Portal</title>
            <style>
                body { font-family: Arial, sans-serif; background-color: #eef2f7; }
                .container { width: 800px; margin: 50px auto; background-color: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); }
                h1 { color: #333; }
                p { font-size: 16px; line-height: 1.6; color: #333; }
                .back { margin-top: 30px; }
                a { text-decoration: none; color: #007BFF; }
                a:hover { text-decoration: underline; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>{{ doc[1] }}</h1>
                <p>{{ doc[2] }}</p>
                <div class="back">
                    <p><a href="{{ url_for('dashboard') }}">Back to Dashboard</a></p>
                </div>
            </div>
        </body>
        </html>
        '''
        return render_template_string(template, doc=doc)
    else:
        return 'Document not found', 404

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.)