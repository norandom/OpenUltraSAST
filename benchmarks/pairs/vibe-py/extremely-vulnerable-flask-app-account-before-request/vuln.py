# Provenance: manuelz120/extremely-vulnerable-flask-app before_request (vuln).
# repo: manuelz120/extremely-vulnerable-flask-app
# commit: d5d8875559e21222bbbaadb7b9f0af592c6eb7fa
# parent: d5d8875559e21222bbbaadb7b9f0af592c6eb7fa
# commit_url: https://github.com/manuelz120/extremely-vulnerable-flask-app/blob/d5d8875559e21222bbbaadb7b9f0af592c6eb7fa/routes/account.py#L118
# cve: 
# license: GPL-3.0
# function: before_request
# relpath: routes/account.py
# provenance: human
# mechanism: source_reaches_sink

def before_request():
    preferences = request.cookies.get('preferences')
    if preferences is None:
        preferences = default_preferences
    else:
        preferences = loads(b64decode(preferences))

    g.preferences = preferences
