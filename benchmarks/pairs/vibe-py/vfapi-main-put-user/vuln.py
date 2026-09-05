# Provenance: naryal2580/vfapi put_user (vuln).
# repo: naryal2580/vfapi
# commit: f36f177e1a32aa49272f4eb52f8be0af3e8f6bc3
# parent: f36f177e1a32aa49272f4eb52f8be0af3e8f6bc3
# commit_url: https://github.com/naryal2580/vfapi/blob/f36f177e1a32aa49272f4eb52f8be0af3e8f6bc3/main.py#L188
# cve: 
# license: MIT
# function: put_user
# relpath: main.py
# provenance: human
# mechanism: source_reaches_sink
# upstream_start: 186

async def put_user(user: User):
    user.password = md5(user.password.encode()).hexdigest()
    query = f'''
INSERT INTO users (
                    name,
                    username,
                    password,
                    address,
                    email,
                    contact
                ) VALUES ( 
                            "{user.name}",
                            "{user.username}",
                            "{user.password}",
                            "{user.address}",
                            "{user.email}",
                            "{user.contact}"
                            );
'''[1:-1]
    await run_sql_query(query, commit=True)
    _id = await run_sql_query('SELECT id from users ORDER BY ROWID DESC limit 1;')
    db_client.vfapi.users.insert_one({
        'id': _id,
        'name': user.name,
        'username': user.username,
        'password': user.password,
        'address': user.address,
        'email': user.email,
        'contact': user.contact
        })
    return {'resp': 'done'}
