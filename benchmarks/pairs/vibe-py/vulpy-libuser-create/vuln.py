# Provenance: fportantier/vulpy create (vuln).
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

def create(username, password):

    conn = sqlite3.connect('db_users.sqlite')
    c = conn.cursor()

    c.execute("INSERT INTO users (username, password, failures, mfa_enabled, mfa_secret) VALUES ('%s', '%s', '%d', '%d', '%s')" %(username, password, 0, 0, ''))

    conn.commit()
    conn.close()
