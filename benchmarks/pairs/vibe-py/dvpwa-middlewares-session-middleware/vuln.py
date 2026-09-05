# Provenance: anxolerd/dvpwa session_middleware (vuln).
# repo: anxolerd/dvpwa
# commit: a1d8f89fac2e57093189853c6527c2b01fc1d9c1
# parent: a1d8f89fac2e57093189853c6527c2b01fc1d9c1
# commit_url: https://github.com/anxolerd/dvpwa/blob/a1d8f89fac2e57093189853c6527c2b01fc1d9c1/sqli/middlewares.py#L20
# cve: 
# license: MIT
# function: session_middleware
# relpath: sqli/middlewares.py
# provenance: human
# mechanism: permissive_default

async def session_middleware(request, handler):
    """Wrapper to Session Middleware factory.
    """
    # Do the trick, by passing app & handler back to original session
    # middleware factory. Do not forget to await on results here as original
    # session middleware factory is also awaitable.
    app = request.app
    storage = RedisStorage(app['redis'], httponly=False)
    middleware = session_middleware_(storage)
    return await middleware(request, handler)
