# Provenance: naryal2580/vfapi delete_user (vuln).
# repo: naryal2580/vfapi
# commit: f36f177e1a32aa49272f4eb52f8be0af3e8f6bc3
# parent: f36f177e1a32aa49272f4eb52f8be0af3e8f6bc3
# commit_url: https://github.com/naryal2580/vfapi/blob/f36f177e1a32aa49272f4eb52f8be0af3e8f6bc3/main.py#L231
# cve: 
# license: MIT
# function: delete_user
# relpath: main.py
# provenance: human
# mechanism: source_reaches_sink

async def delete_user(username: Optional[str] = '', user: Optional[User] = None):
    if username:
        db_client.vfapi.users.delete_one({'username': username})
        await run_sql_query(f'DELETE FROM users WHERE username = "{username}";', commit=True)
        return {'resp': 'done'}
    elif user:
        db_client.vfapi.users.delete_one({'address': user.address})
        await run_sql_query(f'DELETE FROM users WHERE address = {user.address};', commit=True)
    return {'resp': '!done'}
