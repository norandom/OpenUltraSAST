# Provenance: erev0s/VAmPI get_user (vuln).
# repo: erev0s/VAmPI
# commit: 1713b54b601ad29582581eeda4b31fceb1319874
# parent: 1713b54b601ad29582581eeda4b31fceb1319874
# commit_url: https://github.com/erev0s/VAmPI/blob/1713b54b601ad29582581eeda4b31fceb1319874/models/user_model.py#L72
# cve: 
# license: MIT
# function: get_user
# relpath: models/user_model.py
# provenance: human
# mechanism: source_reaches_sink

    def get_user(username):
        if vuln:  # SQLi Injection
            user_query = f"SELECT * FROM users WHERE username = '{username}'"
            query = db.session.execute(text(user_query))
            ret = query.fetchone()
            if ret:
                fin_query = '{"username": "%s", "email": "%s"}' % (ret[1], ret[3])
            else:
                fin_query = None
        else:
            fin_query = User.query.filter_by(username=username).first()
        return fin_query
