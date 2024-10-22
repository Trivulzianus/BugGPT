from flask import Flask, request, render_template_string, redirect, url_for, session

app = Flask(__name__)
app.secret_key = "your_secret_key"

users = {
    "1": {"username": "alice", "password": "wonderland", "profile": "Alice's secret diary..."},
    "2": {"username": "bob", "password": "builder", "profile": "Bob's construction plans..."}
}

@app.route('/')
def home():
    narrative = """
    <h1 style="color: darkslateblue; text-align: center;">Welcome to the Mystic Land of Vulnaria</h1>
    <p style="color: darkgoldenrod;">In the mystical realm of Vulnaria, protectors guard the ancient tomes held within. Rumor has it that a legendary artifact lies hidden, a revelation only for the worthy who can unveil the mysteries shrouded by forgotten deities. Seek, oh valiant adventurer, the path that many fear to tread - unravel the secrets hidden in the tapestry of vulnerability.</p>
    <a href="/login" style="color: darkgreen;">Begin your quest...</a>
    """
    return render_template_string(narrative)

@app.route('/login', methods=['GET', 'POST'])
def login():
    narrative = """
    <h2>Adventurer's Gate</h2>
    <form method="post" style="background-color: lightgray; padding: 20px;">
        <div><label>Username: <input type="text" name="username" /></label></div>
        <div><label>Password: <input type="password" name="password" /></label></div>
        <input type="submit" value="Enter Realm" />
    </form>
    """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        for user_id, user in users.items():
            if user['username'] == username and user['password'] == password:
                session['user_id'] = user_id
                return redirect(url_for('profile', user_id=user_id))
    return render_template_string(narrative)

@app.route('/profile/<user_id>')
def profile(user_id):
    if 'user_id' not in session or session['user_id'] != user_id:
        return "<h2>Alas! The path you seek is shrouded!</h2>", 403
    
    user_profile = users.get(user_id, {}).get('profile', 'Profile lost in time...')
    narrative = f"""
    <h2>Explorer's Sanctuary</h2>
    <p>{user_profile}</p>
    <a href="/" style="color: darkred;">Part ways with Vulnaria</a>
    """
    return render_template_string(narrative)

if __name__ == '__main__':
    app.run(debug=True)