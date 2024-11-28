from flask import Flask, render_template_string, request
import sqlite3

# Create the Flask app
app = Flask(__name__)

# Initialize the database and create a table for users
def init_db():
    conn = sqlite3.connect('social_network.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            name TEXT,
            bio TEXT
        )
    ''')
    # Insert some sample data
    cursor.executemany('''
        INSERT INTO users (username, name, bio) VALUES (?, ?, ?)
    ''', [
        ('jdoe', 'John Doe', 'Love hiking and outdoor adventures.'),
        ('asmith', 'Alice Smith', 'Coffee enthusiast and book lover.'),
        ('bjones', 'Bob Jones', 'Tech geek and coder.')
    ])
    conn.commit()
    conn.close()

# Home page with a search form
@app.route('/', methods=['GET', 'POST'])
def home():
    query = ''
    results = []
    if request.method == 'POST':
        query = request.form.get('username', '')
        # Vulnerable SQL query
        conn = sqlite3.connect('social_network.db')
        cursor = conn.cursor()
        sql_query = "SELECT username, name, bio FROM users WHERE username = '{}'".format(query)
        cursor.execute(sql_query)
        results = cursor.fetchall()
        conn.close()
    return render_template_string('''
    <!doctype html>
    <html lang="en">
    <head>
        <title>FriendSpace - Connect with Friends</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f2f2f2; }
            .container { width: 50%; margin: auto; background-color: #fff; padding: 20px; }
            h1 { text-align: center; }
            .profile { border-bottom: 1px solid #ccc; padding: 10px; }
            .search { text-align: center; margin-bottom: 20px; }
            .search input[type="text"] { width: 80%; padding: 10px; }
            .search input[type="submit"] { padding: 10px 20px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>FriendSpace</h1>
            <div class="search">
                <form method="POST">
                    <input type="text" name="username" placeholder="Search by username" value="{{ query }}">
                    <input type="submit" value="Search">
                </form>
            </div>
            {% if results %}
                {% for user in results %}
                    <div class="profile">
                        <h2>{{ user[1] }} (@{{ user[0] }})</h2>
                        <p>{{ user[2] }}</p>
                    </div>
                {% else %}
                    <p>No users found.</p>
                {% endfor %}
            {% endif %}
        </div>
    </body>
    </html>
    ''', query=query, results=results)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)