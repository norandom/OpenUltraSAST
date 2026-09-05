# Provenance: sgabe/DSVPWA do_BDR (fixed).
# repo: sgabe/DSVPWA
# commit: a06abb306ed3699bb2f073e3f41d3d9c57012819
# parent: a06abb306ed3699bb2f073e3f41d3d9c57012819
# commit_url: https://github.com/sgabe/DSVPWA/blob/a06abb306ed3699bb2f073e3f41d3d9c57012819/dsvpwa/handlers.py#L183
# cve: 
# license: MIT
# function: do_BDR
# relpath: dsvpwa/handlers.py
# provenance: human
# mechanism: source_reaches_sink

    def run(self, handler):
        params = handler.params
        connection = handler.server.connection
        cursor = connection.cursor()

        if 'comment' in params:
            comment = params.get('comment', '')[0]
            cursor.execute('INSERT INTO comments VALUES(NULL, ?, ?)', [comment, time.ctime()])
            connection.commit()
            content = 'Thank you for leaving the comment. Please click <a href=/guestbook?comment=>here</a> to see all comments...'
        else:
            cursor.execute("SELECT id, comment, time FROM comments")
            rows = ""
            for row in cursor.fetchall():
                columns = ""
                for column in row:
                    columns += "".join("<td>{}</td>".format("-" if column is None else column))
                rows += "".join("<tr>{}</tr>".format(columns))

            content = '''
                <div><span>Comment(s):</span></div>
                <table>
                    <thead>
                        <th>id</th>
                        <th>comment</th>
                        <th>time</th>
                    </thead>
                    {}
                </table>'''.format(rows)

        return content
