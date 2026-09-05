# Provenance: naryal2580/vfapi sql_return_users_from_username (fixed).
# repo: naryal2580/vfapi
# commit: f36f177e1a32aa49272f4eb52f8be0af3e8f6bc3
# parent: f36f177e1a32aa49272f4eb52f8be0af3e8f6bc3
# commit_url: https://github.com/naryal2580/vfapi/blob/f36f177e1a32aa49272f4eb52f8be0af3e8f6bc3/main.py#L182
# cve: 
# license: MIT
# function: sql_return_users_from_username
# relpath: main.py
# provenance: human
# mechanism: source_reaches_sink

async def nosql_return_users_from_username(username: str):
    return get_nosql_users({'username': username})
