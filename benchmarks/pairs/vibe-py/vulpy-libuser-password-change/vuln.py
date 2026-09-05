# Provenance: fportantier/vulpy password_change (vuln).
# repo: fportantier/vulpy
# commit: 5249cc8b05a1c37f6b2f757b1cf16a509c327122
# parent: 5249cc8b05a1c37f6b2f757b1cf16a509c327122
# commit_url: https://github.com/fportantier/vulpy/blob/5249cc8b05a1c37f6b2f757b1cf16a509c327122/bad/libuser.py#L53
# cve: 
# license: MIT
# function: password_change
# relpath: bad/libuser.py
# provenance: human
# mechanism: source_reaches_sink

def password_change(username, password):

    conn = sqlite3.connect('db_users.sqlite')
    conn.set_trace_callback(print)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("UPDATE users SET password = '{}' WHERE username = '{}'".format(password, username))
    conn.commit()

    return True
