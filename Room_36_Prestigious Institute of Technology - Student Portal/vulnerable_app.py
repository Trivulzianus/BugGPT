from flask import Flask, render_template_string, request, g
import sqlite3
import re
import html

app = Flask(__name__)

DATABASE = 'institute.db'

# Initialize the database
def init_db():
    with app.app_context():
        db = get_db()
        # Create tables
        db.execute('''
            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                course TEXT NOT NULL
            )
        ''')
        # Insert sample data
        db.executemany('''
            INSERT OR IGNORE INTO students (name, email, course) VALUES (?, ?, ?)
        ''', [
            ('Alice Smith', 'alice@example.com', 'Computer Science'),
            ('Bob Johnson', 'bob@example.com', 'Mathematics'),
            ('Charlie Lee', 'charlie@example.com', 'Physics'),
            ('David Brown', 'david@example.com', 'Engineering'),
            ('Eve Davis', 'eve@example.com', 'Chemistry')
        ])
        db.commit()

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def escape_input(user_input):
    # Escape HTML characters
    return html.escape(user_input)

def sanitize_input(user_input):
    # Supposedly sanitize input by removing dangerous SQL characters
    cleaned = re.sub(r'(--|\;|\')', '', user_input)
    return cleaned

def process_input(user_input):
    # Chain of functions to process input
    escaped = escape_input(user_input)
    sanitized = sanitize_input(escaped)
    return sanitized

def build_query(search_term):
    base_query = "SELECT * FROM students WHERE {}"
    conditions = []

    if search_term:
        term = process_input(search_term)
        # Supposedly safe parameter substitution
        conditions.append("(name LIKE '%{}%' ESCAPE '\\\\' OR course LIKE '%{}%' ESCAPE '\\\\')".format(term, term))
    else:
        conditions.append("1=1")  # No search term provided

    final_query = base_query.format(' AND '.join(conditions))
    return final_query

@app.route('/', methods=['GET', 'POST'])
def index():
    students = None
    if request.method == 'POST':
        search = request.form.get('search', '')
        db = get_db()
        query = build_query(search)
        cursor = db.execute(query)
        students = cursor.fetchall()
    return render_template_string('''
<!doctype html>
<html lang="en">
<head>
    <title>Prestigious Institute of Technology - Student Portal</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 50px; background-color: #f9f9f9; }
        h1 { color: #003366; }
        p { font-size: 1.1em; }
        form { margin-bottom: 30px; }
        input[type="text"] { width: 300px; padding: 8px; font-size: 1em; }
        input[type="submit"] { padding: 8px 15px; font-size: 1em; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #003366; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        footer { margin-top: 50px; text-align: center; font-size: 0.9em; color: #777; }
    </style>
</head>
<body>
    <h1>Welcome to the Prestigious Institute of Technology</h1>
    <p>Our institute is committed to excellence in teaching, learning, and research, and to developing leaders in many disciplines who make a difference globally.</p>
    <h2>Student Search Portal</h2>
    <form method="post">
        <input type="text" name="search" placeholder="Search students by name or course">
        <input type="submit" value="Search">
    </form>
    {% if students %}
    <table>
        <tr><th>Name</th><th>Email</th><th>Course</th></tr>
        {% for student in students %}
        <tr>
            <td>{{ student['name'] }}</td>
            <td>{{ student['email'] }}</td>
            <td>{{ student['course'] }}</td>
        </tr>
        {% endfor %}
    </table>
    {% endif %}
    <footer>
        © {{ current_year }} Prestigious Institute of Technology. All rights reserved.
    </footer>
</body>
</html>
''', students=students, current_year=2023)

if __name__ == '__main__':
    init_db()
    app.)