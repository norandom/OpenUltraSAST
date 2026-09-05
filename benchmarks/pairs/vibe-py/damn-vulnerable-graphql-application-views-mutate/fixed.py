# Provenance: dolevf/Damn-Vulnerable-GraphQL-Application mutate (fixed).
# repo: dolevf/Damn-Vulnerable-GraphQL-Application
# commit: a961308c02d1fb462b192681c336b0739e432da7
# parent: a961308c02d1fb462b192681c336b0739e432da7
# commit_url: https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application/blob/a961308c02d1fb462b192681c336b0739e432da7/core/views.py#L211
# cve: 
# license: MIT
# function: mutate
# relpath: core/views.py
# provenance: human
# mechanism: source_reaches_sink

    def mutate(self, info , username, password) :
        user = User.query.filter_by(username=username, password=password).first()
        Audit.create_audit_entry(info)
        if not user:
            raise Exception('Authentication Failure')
        return Login(
            access_token = create_access_token(username),
            refresh_token = create_refresh_token(username)
        )
