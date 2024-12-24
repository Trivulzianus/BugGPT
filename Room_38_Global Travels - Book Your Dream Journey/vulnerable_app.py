from flask import Flask, render_template_string, request
import sqlite3

# Initialize the Flask application
app = Flask(__name__)

# In-memory SQLite database setup for demonstration purposes
def init_db():
    conn = sqlite3.connect(':memory:')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE bookings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            destination TEXT NOT NULL,
            date TEXT NOT NULL
        )
    ''')
    # Insert some sample data
    c.executemany('''
        INSERT INTO bookings (name, email, destination, date)
        VALUES (?, ?, ?, ?)
    ''', [
        ('Alice Smith', 'alice@example.com', 'Paris', '2023-12-01'),
        ('Bob Johnson', 'bob@example.com', 'New York', '2023-11-15'),
        ('Charlie Lee', 'charlie@example.com', 'Tokyo', '2023-12-20')
    ])
    conn.commit()
    conn.close()

# Route for the home page
@app.route('/')
def home():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Global Travels - Book Your Dream Journey</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; }
            .header { background-color: #4CAF50; padding: 20px; text-align: center; color: white; }
            .container { padding: 20px; }
            .booking-form { background-color: white; padding: 20px; border-radius: 5px; }
            .booking-form input { width: 100%; padding: 10px; margin: 5px 0; }
            .booking-form button { background-color: #4CAF50; color: white; padding: 10px; width: 100%; border: none; }
            .footer { background-color: #ddd; padding: 10px; text-align: center; }
            .bookings-table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            .bookings-table th, .bookings-table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            .bookings-table th { background-color: #f2f2f2; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Global Travels</h1>
            <p>Experience the world like never before</p>
        </div>
        <div class="container">
            <div class="booking-form">
                <h2>Search Bookings</h2>
                <form method="GET" action="/search">
                    <input type="text" name="destination" placeholder="Enter destination" required>
                    <button type="submit">Search</button>
                </form>
            </div>
        </div>
        <div class="footer">
            <p>&copy; 2023 Global Travels. All rights reserved.</p>
        </div>
    </body>
    </html>
    ''')

# Route for searching bookings (Intentionally vulnerable to SQL Injection)
@app.route('/search')
def search():
    destination = request.args.get('destination', '')
    conn = sqlite3.connect(':memory:')
    c = conn.cursor()
    # WARNING: The following line is intentionally vulnerable to SQL Injection
    query = f"SELECT name, email, destination, date FROM bookings WHERE destination = '{destination}'"
    c.execute(query)
    results = c.fetchall()
    conn.close()
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Search Results - Global Travels</title>
        <style>
            /* Same styles as before */
            body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; }
            .header { background-color: #4CAF50; padding: 20px; text-align: center; color: white; }
            .container { padding: 20px; }
            .bookings-table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            .bookings-table th, .bookings-table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            .bookings-table th { background-color: #f2f2f2; }
            .footer { background-color: #ddd; padding: 10px; text-align: center; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Global Travels</h1>
            <p>Search Results</p>
        </div>
        <div class="container">
            {% if results %}
            <table class="bookings-table">
                <tr>
                    <th>Name</th>
                    <th>Email</th>
                    <th>Destination</th>
                    <th>Date</th>
                </tr>
                {% for row in results %}
                <tr>
                    <td>{{ row[0] }}</td>
                    <td>{{ row[1] }}</td>
                    <td>{{ row[2] }}</td>
                    <td>{{ row[3] }}</td>
                </tr>
                {% endfor %}
            </table>
            {% else %}
            <p>No bookings found for the destination "{{ destination }}".</p>
            {% endif %}
            <a href="/">Go Back</a>
        </div>
        <div class="footer">
            <p>&copy; 2023 Global Travels. All rights reserved.</p>
        </div>
    </body>
    </html>
    ''', results=results, destination=destination)

if __name__ == '__main__':
    init_db()
    app.)