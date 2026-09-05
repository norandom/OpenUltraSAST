# Provenance: anotherik/ThreatByte dashboard (vuln).
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

def dashboard():
    # Check if the user is logged in
    if 'username' in session:
        
        search_query = request.args.get('search', '')

        # Get user_id from the session username
        with get_db_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT id FROM users WHERE username = ?"
            cursor.execute(query, (session['username'],))
            user = cursor.fetchone()
            user_id = user['id']

        if search_query:
            s_query = f"SELECT filename FROM files WHERE user_id = {user_id} AND filename LIKE '%{search_query}%'"
            cursor.execute(s_query)
        else:
            cursor.execute("SELECT filename FROM files WHERE user_id = ?", (user_id,))
        files = [row['filename'] for row in cursor.fetchall()]

        return render_template('dashboard.html', files=files, search_query=search_query)
    else:
        return redirect(url_for('login'))
