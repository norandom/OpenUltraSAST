# Provenance: kolega-ai/realvuln-python-insecure-app try_hack_me (vuln).
# repo: kolega-ai/realvuln-python-insecure-app
# commit: 80b894a2f754590747a31c92b2088be086421953
# parent: 80b894a2f754590747a31c92b2088be086421953
# commit_url: https://github.com/kolega-ai/realvuln-python-insecure-app/blob/80b894a2f754590747a31c92b2088be086421953/app/main.py#L41
# cve: 
# license: GPL-3.0
# function: try_hack_me
# relpath: app/main.py
# provenance: human
# mechanism: source_reaches_sink

async def try_hack_me(name: str = config.SUPER_SECRET_NAME):
    """
    Root endpoint that greets the user and provides a random text.

    Args:
        name (str, optional): Name of the user. Defaults to SUPER_SECRET_NAME.

    Returns:
        str: HTML content with a greeting and a public ip response.
    """
    try:
        # Get the public IP address from an external service
        public_ip_response = requests.get(config.PUBLIC_IP_SERVICE_URL)
        public_ip_response.raise_for_status()
    except (requests.HTTPError, requests.exceptions.InvalidSchema):
        public_ip = "Unknown"
    else:
        public_ip = public_ip_response.text
    name = name or config.SUPER_SECRET_NAME
    content = f"<h1>Hello, {name}!</h1><h2>Public IP: <code>{public_ip}</code></h2>"
    # https://fastapi.tiangolo.com/advanced/custom-response/#return-a-response
    # FIXME: return HTMLResponse(content)
    return Template(content).render()
