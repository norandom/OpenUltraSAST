# Provenance: erev0s/VAmPI update_password (vuln).
# repo: erev0s/VAmPI
# commit: 1713b54b601ad29582581eeda4b31fceb1319874
# parent: 1713b54b601ad29582581eeda4b31fceb1319874
# commit_url: https://github.com/erev0s/VAmPI/blob/1713b54b601ad29582581eeda4b31fceb1319874/api_views/users.py#L187
# cve: 
# license: MIT
# function: update_password
# relpath: api_views/users.py
# provenance: human
# mechanism: missing_auth_guard

def update_password(username):
    request_data = request.get_json()
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    else:
        if request_data.get('password'):
            if vuln:  # Unauthorized update of password of another user
                user = User.query.filter_by(username=username).first()
                if user:
                    user.password = request_data.get('password')
                    db.session.commit()
                else:
                    return Response(error_message_helper("User Not Found"), 400, mimetype="application/json")
            else:
                user = User.query.filter_by(username=resp['sub']).first()
                user.password = request_data.get('password')
                db.session.commit()
            responseObject = {
                'status': 'success',
                'Password': 'Updated.'
            }
            return Response(json.dumps(responseObject), 204, mimetype="application/json")
        else:
            return Response(error_message_helper("Malformed Data"), 400, mimetype="application/json")
