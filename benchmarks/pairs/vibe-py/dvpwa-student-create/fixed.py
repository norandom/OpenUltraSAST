# Provenance: anxolerd/dvpwa create (fixed).
# repo: anxolerd/dvpwa
# commit: a1d8f89fac2e57093189853c6527c2b01fc1d9c1
# parent: a1d8f89fac2e57093189853c6527c2b01fc1d9c1
# commit_url: https://github.com/anxolerd/dvpwa/blob/a1d8f89fac2e57093189853c6527c2b01fc1d9c1/sqli/dao/student.py#L42
# cve: 
# license: MIT
# function: create
# relpath: sqli/dao/student.py
# provenance: human
# mechanism: source_reaches_sink

    async def get_by_username(conn: Connection, username: str):
        async with conn.cursor() as cur:
            await cur.execute(
                'SELECT id, first_name, middle_name, last_name, '
                'username, pwd_hash, is_admin FROM users WHERE username = %s',
                (username,),
            )
            return User.from_raw(await cur.fetchone())
