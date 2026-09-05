# Provenance: LinuxUser255/Vulnerable_Python_Apps do_GET (fixed).
# repo: LinuxUser255/Vulnerable_Python_Apps
# commit: 6336c77e6db523a5df34c4b628dff4159110797a
# parent: 6336c77e6db523a5df34c4b628dff4159110797a
# commit_url: https://github.com/LinuxUser255/Vulnerable_Python_Apps/blob/6336c77e6db523a5df34c4b628dff4159110797a/Directory_Traversal/Dir_Traversal.py#L22
# cve: 
# license: GPL-3.0
# function: do_GET
# relpath: Directory_Traversal/Dir_Traversal.py
# provenance: human
# mechanism: path_join_user_input

def get_post(post_id):
    conn = get_db_connection()  # SQL configured to schema.sql
    post = conn.execute('SELECT * FROM posts WHERE id = ?',
                        (post_id,)).fetchone()
    conn.close()
    if post is None:
        abort(404)
    return post
