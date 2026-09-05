# Provenance: anotherik/ThreatByte delete (vuln).
# repo: anotherik/ThreatByte
# commit: c4db46f72586c4ecb65859051ea037018dbf0e5e
# parent: c4db46f72586c4ecb65859051ea037018dbf0e5e
# commit_url: https://github.com/anotherik/ThreatByte/blob/c4db46f72586c4ecb65859051ea037018dbf0e5e/server/api/v1/api_v1.py#L223
# cve: 
# license: MIT
# function: delete
# relpath: server/api/v1/api_v1.py
# provenance: human
# mechanism: missing_auth_guard

    def delete(self, user_id):
        """
            Delete a user from the application.
        """
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            user = cursor.fetchone()
            if user:
                cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
                conn.commit()
                response = make_response(jsonify({'message': 'User deleted successfully'}), 200)
                return response
            else:
                response = make_response(jsonify({'error': 'User not found'}), 404)
                return response
