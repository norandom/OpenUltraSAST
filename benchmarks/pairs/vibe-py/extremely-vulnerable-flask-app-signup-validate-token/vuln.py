# Provenance: manuelz120/extremely-vulnerable-flask-app validate_token (vuln).
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

def validate_token(code: str, session: Session) -> Union[str, None]:
    try:
        result = session.execute(
            text(f"""
                SELECT id, code FROM {RegistrationCode.__tablename__} WHERE code = '{code}'
            """)).first()

        if result is None:
            return None

        return result.id
    except OperationalError:
        return None
