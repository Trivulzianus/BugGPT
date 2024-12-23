from flask import Flask, render_template_string, request, redirect, url_for, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize the Flask application
app = Flask(__name__)
app.secret_key = 'YourSecretKeyHere'  # Replace with your secret key

# Initialize the database
def init_db():
    conn = sqlite3.connect('booking.db')
    cursor = conn.cursor()
    # Create users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )''')

    # Create bookings table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS bookings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        booking_details TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')

    # Insert sample users
    users = [
        ('alice', generate_password_hash('alicepass')),
        ('bob', generate_password_hash('bobpass')),
        ('charlie', generate_password_hash('charliepass')),
    ]
    cursor.executemany('INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)', users)

    # Insert sample bookings
    bookings = [
        (1, 'Booking Details for Alice: Hotel California, 5 nights'),
        (2, 'Booking Details for Bob: Grand Budapest Hotel, 3 nights'),
        (3, 'Booking Details for Charlie: The Plaza Hotel, 2 nights'),
    ]
    cursor.executemany('INSERT OR IGNORE INTO bookings (user_id, booking_details) VALUES (?, ?)', bookings)

    conn.commit()
    conn.close()

# Call the database initialization function
init_db()

# HTML templates with basic styling
login_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>BookNow | Login</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f2f2f2; }
        .container { width: 300px; margin: 100px auto; padding: 25px; background-color: white; border-radius: 10px; }
        h2 { text-align: center; }
        input[type=text], input[type=password] { width: 100%; padding: 10px; margin: 5px 0 15px 0; border: none; background: #f1f1f1; }
        button { background-color: #4CAF50; color: white; padding: 10px; width: 100%; border: none; border-radius: 5px; cursor: pointer; }
        button:hover { opacity: 0.8; }
        .error { color: red; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Login to BookNow</h2>
        {% if error %}
            <p class="error">{{ error }}</p>
        {% endif %}
        <form method="post">
            <input type="text" name="username" placeholder="Username" required autofocus>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
'''

booking_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>BookNow | My Booking</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #e5eff1; }
        .container { width: 500px; margin: 50px auto; padding: 25px; background-color: white; border-radius: 10px; }
        h2 { text-align: center; }
        p { font-size: 18px; }
        a { display: block; text-align: center; margin-top: 20px; text-decoration: none; color: #4CAF50; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Your Booking Details</h2>
        <p>{{ booking_details }}</p>
        <a href="{{ url_for('logout') }}">Logout</a>
    </div>
</body>
</html>
'''

# Route for handling the login page logic
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Retrieve form data
        username = request.form['username']
        password = request.form['password']

        # Connect to the database
        conn = sqlite3.connect('booking.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, password FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()

        # Validate credentials
        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            return redirect(url_for('my_booking'))
        else:
            error = 'Invalid username or password. Please try again.'
            return render_template_string(login_template, error=error)
    else:
        return render_template_string(login_template)

# Route for displaying the booking details
@app.route('/my_booking')
def my_booking():
    if 'user_id' in session:
        user_id = session['user_id']

        # Intentional IDOR vulnerability: user can supply any user_id via query parameter
        requested_user_id = request.args.get('user_id', user_id)

        # Connect to the database
        conn = sqlite3.connect('booking.db')
        cursor = conn.cursor()
        cursor.execute('SELECT booking_details FROM bookings WHERE user_id = ?', (requested_user_id,))
        booking = cursor.fetchone()
        conn.close()

        if booking:
            return render_template_string(booking_template, booking_details=booking[0])
        else:
            return render_template_string(booking_template, booking_details='No booking details found.')
    else:
        return redirect(url_for('login'))

# Route to handle logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)