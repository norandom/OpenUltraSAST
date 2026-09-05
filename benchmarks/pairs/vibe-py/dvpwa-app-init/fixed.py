# Provenance: anxolerd/dvpwa init (fixed).
# repo: anxolerd/dvpwa
# commit: a1d8f89fac2e57093189853c6527c2b01fc1d9c1
# parent: a1d8f89fac2e57093189853c6527c2b01fc1d9c1
# commit_url: https://github.com/anxolerd/dvpwa/blob/a1d8f89fac2e57093189853c6527c2b01fc1d9c1/sqli/app.py#L35
# cve: 
# license: MIT
# function: init
# relpath: sqli/app.py
# provenance: human
# mechanism: permissive_default

    async def get_by_username(conn: Connection, username: str):
        async with conn.cursor() as cur:
            await cur.execute(
                'SELECT id, first_name, middle_name, last_name, '
                'username, pwd_hash, is_admin FROM users WHERE username = %s',
                (username,),
            )
            return User.from_raw(await cur.fetchone())
