# Provenance: anotherik/ThreatByte get (vuln).
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

    def get(self):
        """
        Retrieves the profile information of a user based on the provided user ID.
        """
        args = profile_query.parse_args()
        user_id = args.get('user_id')

        with get_db_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT username, email, country, role, permissions, team FROM users WHERE id = ?"
            cursor.execute(query, (user_id,))
            user_profile = cursor.fetchone()

        if user_profile:
            return dict(user_profile), 200
        else:
            return {'error': 'User profile not found'}, 404
