from flask import Flask, request, render_template_string, redirect, url_for, session
import requests

app = Flask(__name__)
app.secret_key = 'SuperSecretKey'

def is_valid_url(url):
    return url.startswith('http://') or url.startswith('https://')

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form.get('url')
        if is_valid_url(url):
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    return render_template_string("""
                        <!DOCTYPE html>
                        <html lang="en">
                        <head>
                            <meta charset="UTF-8">
                            <meta name="viewport" content="width=device-width, initial-scale=1.0">
                            <title>The Grand Cyber Adventure</title>
                            <style>
                                body { background: linear-gradient(to right, #ff7e5f, #feb47b); color: #fff; font-family: Arial, sans-serif; text-align: center; margin: 0; padding: 0; }
                                .container { padding: 20px; }
                                .header { font-size: 2em; margin-bottom: 20px; }
                                .narrative { font-size: 1.2em; margin-bottom: 20px; }
                                .input { margin-bottom: 10px; }
                                .button { background-color: #ff4b2b; color: #fff; border: none; padding: 10px 20px; cursor: pointer; }
                            </style>
                        </head>
                        <body>
                            <div class="container">
                                <div class="header">Welcome to The Grand Cyber Adventure</div>
                                <div class="narrative">
                                    You're on a journey through the vast lands of Cyberia, a realm where information flows like rivers.
                                    Your mission: retrieve the hidden scroll from the Chamber of Secrets. Use the enchanted URL to unveil its secrets.
                                </div>
                                <form method="post">
                                    <input type="text" class="input" name="url" placeholder="Enter the mystical URL" required>
                                    <button type="submit" class="button">Reveal the Mystical Scroll</button>
                                </form>
                                <div class="response">{{ response }}</div>
                            </div>
                        </body>
                        </html>
                    """, response=response.text)
                return "<h1>Failed to retrieve content. Perhaps it's a trap!</h1>"
            except Exception as e:
                return f"<h1>An error occurred: {str(e)}</h1>"
        else:
            return "<h1>Invalid URL format. Beware of false paths in Cyberia!</h1>"

    return render_template_string("""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>The Grand Cyber Adventure</title>
            <style>
                body { background: linear-gradient(to right, #00c6ff, #0072ff); color: #fff; font-family: Arial, sans-serif; text-align: center; margin: 0; padding: 0; }
                .container { padding: 20px; }
                .header { font-size: 2em; margin-bottom: 20px; }
                .narrative { font-size: 1.2em; margin-bottom: 20px; }
                .input { margin-bottom: 10px; }
                .button { background-color: #005bea; color: #fff; border: none; padding: 10px 20px; cursor: pointer; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">Welcome to The Grand Cyber Adventure</div>
                <div class="narrative">
                    You're on a journey through the vast lands of Cyberia, a realm where information flows like rivers.
                    Your mission: retrieve the hidden scroll from the Chamber of Secrets. Use the enchanted URL to unveil its secrets.
                </div>
                <form method="post">
                    <input type="text" class="input" name="url" placeholder="Enter the mystical URL" required>
                    <button type="submit" class="button">Reveal the Mystical Scroll</button>
                </form>
            </div>
        </body>
        </html>
    """)

if __name__ == '__main__':
    app.run(debug=True)