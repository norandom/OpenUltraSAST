# Provenance: anxolerd/dvpwa create (vuln).
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

    async def create(conn: Connection, name: str):
        q = ("INSERT INTO students (name) "
             "VALUES ('%(name)s')" % {'name': name})
        async with conn.cursor() as cur:
            await cur.execute(q)
