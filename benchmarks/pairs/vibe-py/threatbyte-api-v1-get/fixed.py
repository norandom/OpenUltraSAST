# Provenance: anotherik/ThreatByte get (fixed).
# repo: anotherik/ThreatByte
# commit: c4db46f72586c4ecb65859051ea037018dbf0e5e
# parent: c4db46f72586c4ecb65859051ea037018dbf0e5e
# commit_url: https://github.com/anotherik/ThreatByte/blob/c4db46f72586c4ecb65859051ea037018dbf0e5e/server/api/v1/api_v1.py#L154
# cve: 
# license: MIT
# function: get
# relpath: server/api/v1/api_v1.py
# provenance: human
# mechanism: missing_auth_guard
# upstream_start: 103

@ns.route('/login')
class UserLogin(Resource):
    @ns.expect(login_model)
    @ns.response(200, 'Login successful', login_response_model)
    @ns.response(400, 'Please provide username and password')
    @ns.response(401, 'Invalid username or password')
    @ns.response(405, 'Method not allowed')
    def post(self):
        """
        Handles user login.
        """
        data = request.get_json()  # Get data from request body
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return {'error': 'Please provide username and password'}, 400
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM users WHERE username = ? OR email = ?"
            cursor.execute(query, (username, username))
            user = cursor.fetchone()

        if user and user['password'] == custom_hash(password):
            
            # Generate JWT
            token = jwt.encode({
                'username': username,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)  # Token expires in 24 hours
            }, Config.SECRET_KEY, algorithm='HS256')
            

            # Update last_login timestamp
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET last_login = ? WHERE username = ?", (datetime.datetime.now(), username))
                conn.commit()

            return {'message': 'Login successful', 'token': token}, 200
        else:
            return {'error': 'Invalid username or password'}, 401
