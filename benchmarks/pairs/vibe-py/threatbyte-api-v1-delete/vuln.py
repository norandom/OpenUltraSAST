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
# upstream_start: 215

@ns.route('/delete-user/<int:user_id>')
@ns.doc(description='Delete a user from the database without proper authorization checks. '
                    'This endpoint represents a Broken Function Level Authorization vulnerability.',
       responses={200: ('User successfully deleted', delete_model),
                  404: ('User not found', error_model)})
class UserDelete(Resource):
    #@token_required
    #def delete(self, current_user, user_id):
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
