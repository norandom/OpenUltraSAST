# Provenance: fportantier/vulpy login (vuln).
# repo: fportantier/vulpy
# commit: 5249cc8b05a1c37f6b2f757b1cf16a509c327122
# parent: 5249cc8b05a1c37f6b2f757b1cf16a509c327122
# commit_url: https://github.com/fportantier/vulpy/blob/5249cc8b05a1c37f6b2f757b1cf16a509c327122/bad/libuser.py#L12
# cve: 
# license: MIT
# function: login
# relpath: bad/libuser.py
# provenance: human
# mechanism: source_reaches_sink

def login(username, password):

    conn = sqlite3.connect('db_users.sqlite')
    conn.set_trace_callback(print)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    user = c.execute("SELECT * FROM users WHERE username = '{}' and password = '{}'".format(username, password)).fetchone()

    if user:
        return user['username']
    else:
        return False
