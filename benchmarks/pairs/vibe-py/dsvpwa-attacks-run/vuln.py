# Provenance: sgabe/DSVPWA run (vuln).
# repo: sgabe/DSVPWA
# commit: a06abb306ed3699bb2f073e3f41d3d9c57012819
# parent: a06abb306ed3699bb2f073e3f41d3d9c57012819
# commit_url: https://github.com/sgabe/DSVPWA/blob/a06abb306ed3699bb2f073e3f41d3d9c57012819/dsvpwa/attacks.py#L39
# cve: 
# license: MIT
# function: run
# relpath: dsvpwa/attacks.py
# provenance: human
# mechanism: source_reaches_sink

    def run(self, handler):
        params = handler.params
        cursor = handler.server.connection.cursor()

        id = '9999999' if 'id' not in params else params['id'][0]
        try:
            cursor.execute("SELECT id, username, firstname, lastname, email, session FROM users WHERE id=" + id)
        except sqlite3.OperationalError as e:
            return e

        rows = ""
        for row in cursor.fetchall():
            columns = ""
            for column in row:
                columns += "".join("<td>{}</td>".format("-" if column is None else column))
            rows += "".join("<tr>{}</tr>".format(columns))

        content = """
            <table class="table">
                <thead>
                    <th scope="col">ID</th>
                    <th scope="col">Username</th>
                    <th scope="col">First name</th>
                    <th scope="col">Last name</th>
                    <th scope="col">E-mail address</th>
                    <th scope="col">Session</th>
                </thead>
                {}
            </table>
        """.format(rows)

        return content
