# Provenance: manuelz120/extremely-vulnerable-flask-app search (fixed).
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

def do_login():
    form = LoginForm(request.form)

    if not form.validate():
        flash(dumps(form.errors), 'error')
    else:
        with Session() as session:
            user = session.query(User).filter(
                User.email == form.email.data).first()
            if user is not None and checkpw(
                    form.password.data.encode('utf-8'),
                    user.password.encode('utf-8')) and login_user(user):
                return redirect("/")

    flash('Invalid Credentials!', 'warning')
    logout_user()

    return redirect("/")
