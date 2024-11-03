from flask import Flask, render_template_string, request, redirect, url_for
import datetime

app = Flask(__name__)

# In-memory storage for feedback messages
feedback_list = []

@app.route('/')
def home():
    return render_template_string(home_page())

@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    global feedback_list
    if request.method == 'POST':
        name = request.form['name']
        message = request.form['message']
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # Stored without sanitization - Stored XSS vulnerability
        feedback_list.append({'name': name, 'message': message, 'timestamp': timestamp})
        return redirect(url_for('feedback'))
    else:
        return render_template_string(feedback_page(), feedbacks=feedback_list)

def home_page():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Secure Bank - Your Trusted Financial Partner</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f5f5f5; margin: 0; }
            .header { background-color: #004080; color: white; padding: 20px; text-align: center; }
            .navigation { overflow: hidden; background-color: #333; }
            .navigation a { float: left; display: block; color: #f2f2f2; text-align: center;
                            padding: 14px 16px; text-decoration: none; }
            .navigation a:hover { background-color: #ddd; color: black; }
            .content { padding: 20px; }
            .footer { background-color: #004080; color: white; text-align: center; padding: 10px;
                      position: fixed; bottom: 0; width: 100%; }
            .banner { background-image: url('https://example.com/banner.jpg'); background-size: cover;
                      height: 200px; }
            .services { display: flex; }
            .service { flex: 1; padding: 20px; }
            .service h3 { color: #004080; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Secure Bank</h1>
            <p>Your Trusted Financial Partner</p>
        </div>
        <div class="navigation">
            <a href="/">Home</a>
            <a href="/feedback">Feedback</a>
            <a href="#">Services</a>
            <a href="#">About Us</a>
            <a href="#">Contact</a>
        </div>
        <div class="banner"></div>
        <div class="content">
            <h2>Welcome to Secure Bank</h2>
            <p>At Secure Bank, we are committed to providing top-notch financial services and solutions to meet your needs.</p>
            <div class="services">
                <div class="service">
                    <h3>Online Banking</h3>
                    <p>Manage your accounts anytime, anywhere with our secure online banking platform.</p>
                </div>
                <div class="service">
                    <h3>Loans</h3>
                    <p>Competitive rates and flexible terms for personal and business loans.</p>
                </div>
                <div class="service">
                    <h3>Investments</h3>
                    <p>Diversify your portfolio with our expert investment services.</p>
                </div>
            </div>
        </div>
        <div class="footer">
            &copy; 2023 Secure Bank. All rights reserved.
        </div>
    </body>
    </html>
    '''

def feedback_page():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Secure Bank - Feedback</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f5f5f5; margin: 0; }
            .header { background-color: #004080; color: white; padding: 20px; text-align: center; }
            .navigation { overflow: hidden; background-color: #333; }
            .navigation a { float: left; display: block; color: #f2f2f2; text-align: center;
                            padding: 14px 16px; text-decoration: none; }
            .navigation a:hover { background-color: #ddd; color: black; }
            .content { padding: 20px; }
            .feedback { background-color: white; padding: 15px; margin-bottom: 15px; border-radius: 5px;
                        box-shadow: 0 0 10px rgba(0,0,0,0.1); }
            .footer { background-color: #004080; color: white; text-align: center; padding: 10px;
                      position: fixed; bottom: 0; width: 100%; }
            .feedback-form { background-color: #e0e0e0; padding: 20px; border-radius: 5px; }
            .feedback-form input, .feedback-form textarea { width: 100%; padding: 10px; margin: 5px 0;
                                                           border: 1px solid #ccc; border-radius: 4px; }
            .feedback-form button { background-color: #004080; color: white; padding: 10px 20px;
                                    border: none; border-radius: 4px; cursor: pointer; }
            .feedback-form button:hover { background-color: #003366; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Secure Bank</h1>
            <p>Your Trusted Financial Partner</p>
        </div>
        <div class="navigation">
            <a href="/">Home</a>
            <a href="/feedback">Feedback</a>
            <a href="#">Services</a>
            <a href="#">About Us</a>
            <a href="#">Contact</a>
        </div>
        <div class="content">
            <h2>Customer Feedback</h2>
            {% for feedback in feedbacks %}
            <div class="feedback">
                <p><strong>{{ feedback.name }}</strong> <em>{{ feedback.timestamp }}</em></p>
                <p>{{ feedback.message }}</p>
            </div>
            {% endfor %}
            <h3>Leave Your Feedback</h3>
            <div class="feedback-form">
                <form method="post" action="/feedback">
                    <p>
                        <label for="name">Name:</label>
                        <input type="text" name="name" id="name" required>
                    </p>
                    <p>
                        <label for="message">Message:</label>
                        <textarea name="message" id="message" rows="5" required></textarea>
                    </p>
                    <p>
                        <button type="submit">Submit Feedback</button>
                    </p>
                </form>
            </div>
        </div>
        <div class="footer">
            &copy; 2023 Secure Bank. All rights reserved.
        </div>
    </body>
    </html>
    '''

if __name__ == '__main__':
    app.run(debug=True)