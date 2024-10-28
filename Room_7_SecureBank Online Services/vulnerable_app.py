from flask import Flask, render_template_string, request, redirect, url_for
import sqlite3

# Initialize the Flask application
app = Flask(__name__)

# In-memory database setup (SQLite)
def init_db():
    conn = sqlite3.connect(':memory:')
    c = conn.cursor()
    c.execute('CREATE TABLE feedback (id INTEGER PRIMARY KEY AUTOINCREMENT, comments TEXT)')
    conn.commit()
    return conn

db_conn = init_db()

# Home page route
@app.route('/')
def home():
    # Fetch all feedback comments to display
    c = db_conn.cursor()
    c.execute('SELECT comments FROM feedback')
    feedback_list = c.fetchall()
    feedback_html = ''.join([f"<p>{comment[0]}</p>" for comment in feedback_list])

    # Render the home page with feedback
    home_page = f'''
    <html>
        <head>
            <title>SecureBank Online Services</title>
            <style>
                body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; }}
                .container {{ width: 80%; margin: auto; overflow: hidden; }}
                #feedback {{ background: #fff; padding: 20px; margin-top: 20px; }}
                #feedback p {{ background: #e4e4e4; padding: 10px; }}
                #footer {{ background: #333; color: #fff; text-align: center; padding: 10px; margin-top: 20px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Welcome to SecureBank Online Services</h1>
                <p>Your trusted partner in financial security.</p>
                <h2>Customer Feedback</h2>
                <div id="feedback">
                    {feedback_html}
                </div>
                <h3>Leave Your Feedback</h3>
                <form action="/submit_feedback" method="POST">
                    <textarea name="comments" rows="4" cols="50" placeholder="Enter your comments here..."></textarea><br/>
                    <input type="submit" value="Submit">
                </form>
            </div>
            <div id="footer">
                &copy; 2023 SecureBank. All rights reserved.
            </div>
        </body>
    </html>
    '''
    return render_template_string(home_page)

# Feedback submission route
@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    comments = request.form['comments']

    # Insert the feedback into the database (Stored XSS vulnerability here)
    c = db_conn.cursor()
    c.execute('INSERT INTO feedback (comments) VALUES (?)', (comments,))
    db_conn.commit()

    return redirect(url_for('home'))

# Run the application
if __name__ == '__main__':
    app.run(debug=True)