# Provenance: manuelz120/extremely-vulnerable-flask-app search (vuln).
# repo: manuelz120/extremely-vulnerable-flask-app
# commit: d5d8875559e21222bbbaadb7b9f0af592c6eb7fa
# parent: d5d8875559e21222bbbaadb7b9f0af592c6eb7fa
# commit_url: https://github.com/manuelz120/extremely-vulnerable-flask-app/blob/d5d8875559e21222bbbaadb7b9f0af592c6eb7fa/routes/account.py#L33
# cve: 
# license: GPL-3.0
# function: search
# relpath: routes/account.py
# provenance: human
# mechanism: source_reaches_sink

def search():
    search_param = request.args.get('search', '')
    with Session() as session:
        session.query(Note)

        personal_notes = session.query(Note).filter(
            Note.user_id == current_user.id,
            text(f"text like '%{search_param}%'")).all()
        return render_template(
            'search.html',
            search=search_param,
            personal_notes=personal_notes,
        )
