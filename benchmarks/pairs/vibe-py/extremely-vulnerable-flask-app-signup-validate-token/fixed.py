# Provenance: manuelz120/extremely-vulnerable-flask-app validate_token (fixed).
# repo: manuelz120/extremely-vulnerable-flask-app
# commit: d5d8875559e21222bbbaadb7b9f0af592c6eb7fa
# parent: d5d8875559e21222bbbaadb7b9f0af592c6eb7fa
# commit_url: https://github.com/manuelz120/extremely-vulnerable-flask-app/blob/d5d8875559e21222bbbaadb7b9f0af592c6eb7fa/routes/signup.py#L15
# cve: 
# license: GPL-3.0
# function: validate_token
# relpath: routes/signup.py
# provenance: human
# mechanism: source_reaches_sink

def do_signup():
    form = RegistrationForm(request.form)

    if not form.validate():
        flash(dumps(form.errors), 'error')
    else:
        with Session() as session:
            user_already_exists = session.query(
                session.query(User).where(
                    User.email == form.email.data).exists()).scalar()

            code = form.registration_code.data
            token_id = validate_token(code, session)
            if token_id is None:
                flash("Invalid registration code", 'warning')
                return redirect("/signup")

            token = session.get(RegistrationCode, token_id)
            if token.code != code:
                flash("Unexpected registration code mismatch", 'error')
                return redirect("/signup")

            session.delete(token)

            if user_already_exists:
                flash("User already exists", 'warning')
                return redirect("/signup")

            user = User(
                form.email.data,
                hashpw(form.password.data.encode('utf-8'), gensalt()).decode())

            session.add(user)
            session.commit()

    return redirect('/home')
