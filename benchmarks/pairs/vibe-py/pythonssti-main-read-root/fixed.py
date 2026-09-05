# Provenance: TheWation/PythonSSTI read_root (fixed).
# repo: TheWation/PythonSSTI
# commit: 76339c27d5a870c0a81bad6aee5f9bd516592145
# parent: 76339c27d5a870c0a81bad6aee5f9bd516592145
# commit_url: https://github.com/TheWation/PythonSSTI/blob/76339c27d5a870c0a81bad6aee5f9bd516592145/main.py#L14
# cve: 
# license: MIT
# function: read_root
# relpath: main.py
# provenance: human
# mechanism: source_reaches_sink

async def read_root(username=None):

    username = username or "Guest"
    Jinja2 = Environment()

    # Vulnerable Implementation
    output = Jinja2.from_string("Welcome " + username + "!").render()

    # Safe Implementation
    # output = Jinja2.from_string("Welcome {{ user_name }}!").render(user_name=username)

    return HTMLResponse(content=output)
