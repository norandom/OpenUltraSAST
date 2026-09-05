# Provenance: erev0s/VAmPI get_user (fixed).
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

def register_user():
    request_data = request.get_json()
    # check if user already exists
    user = User.query.filter_by(username=request_data.get('username')).first()
    if not user:
        try:
            # validate the data are in the correct form
            jsonschema.validate(request_data, register_user_schema)
            if vuln and 'admin' in request_data:  # User is possible to define if she/he wants to be an admin !!
                if request_data['admin']:
                    admin = True
                else:
                    admin = False
                user = User(username=request_data['username'], password=request_data['password'],
                            email=request_data['email'], admin=admin)
            else:
                user = User(username=request_data['username'], password=request_data['password'],
                            email=request_data['email'])
            db.session.add(user)
            db.session.commit()

            responseObject = {
                'status': 'success',
                'message': 'Successfully registered. Login to receive an auth token.'
            }

            return Response(json.dumps(responseObject), 200, mimetype="application/json")
        except jsonschema.exceptions.ValidationError as exc:
            return Response(error_message_helper(exc.message), 400, mimetype="application/json")
    else:
        return Response(error_message_helper("User already exists. Please Log in."), 200, mimetype="application/json")
