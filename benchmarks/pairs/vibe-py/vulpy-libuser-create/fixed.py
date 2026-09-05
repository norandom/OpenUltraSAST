# Provenance: fportantier/vulpy create (fixed).
# repo: fportantier/vulpy
# commit: 5249cc8b05a1c37f6b2f757b1cf16a509c327122
# parent: 5249cc8b05a1c37f6b2f757b1cf16a509c327122
# commit_url: https://github.com/fportantier/vulpy/blob/5249cc8b05a1c37f6b2f757b1cf16a509c327122/bad/libuser.py#L25
# cve: 
# license: MIT
# function: create
# relpath: bad/libuser.py
# provenance: human
# mechanism: source_reaches_sink

def get_posts(username):

    conn = sqlite3.connect('db_posts.sqlite')
    conn.set_trace_callback(print)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    rows = c.execute("SELECT * FROM posts WHERE username = ? ORDER BY date DESC", (username,)).fetchall()

    posts = [ dict(zip(row.keys(), row)) for row in rows ]

    return posts
