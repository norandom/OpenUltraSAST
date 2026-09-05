# Provenance: anotherik/ThreatByte dashboard (fixed).
# repo: anotherik/ThreatByte
# commit: c4db46f72586c4ecb65859051ea037018dbf0e5e
# parent: c4db46f72586c4ecb65859051ea037018dbf0e5e
# commit_url: https://github.com/anotherik/ThreatByte/blob/c4db46f72586c4ecb65859051ea037018dbf0e5e/server/routes.py#L137
# cve: 
# license: MIT
# function: dashboard
# relpath: server/routes.py
# provenance: human
# mechanism: source_reaches_sink

def login():
    """
    Handles user login.

    On GET request:
    Renders the login page.

    On POST request:
    Retrieves the username and password from the login form.
    Queries the database for the user based on the provided username.
    Checks if the provided password matches the hashed password stored in the database.
    If authentication succeeds, stores the username in the session and redirects to the dashboard.
    If authentication fails, renders the login page with an error message.
    """
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            return render_template('login.html', error='Please provide username and password')
        
        # Query the database for the user using parameterized query
        with get_db_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM users WHERE username = ? OR email = ?"
            cursor.execute(query, (username,username))
            user = cursor.fetchone()
        
        # Check if the user exists and the password matches
        if user and user['password'] == custom_hash(password):
            session['username'] = user['username']
            session['user_id'] = user['id']

            # Update last_login timestamp
            cursor.execute("UPDATE users SET last_login = ? WHERE username = ?", (datetime.datetime.now(), username))
            conn.commit()
            conn.close()

            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid username or password')
    return render_template('login.html')
