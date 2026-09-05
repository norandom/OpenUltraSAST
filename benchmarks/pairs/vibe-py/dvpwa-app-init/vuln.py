# Provenance: anxolerd/dvpwa init (vuln).
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

def init(argv):
    ap = ArgumentParser()
    commandline.standard_argparse_options(ap, default_config='./config/dev.yaml')
    options = ap.parse_args(argv)

    config = commandline.config_from_options(options, CONFIG_SCHEMA)

    app = Application(
        debug=True,
        middlewares=[
            session_middleware,
            # csrf_middleware,
            error_middleware,
        ]
    )
    app['config'] = config

    setup_jinja(app, loader=PackageLoader('sqli', 'templates'),
                context_processors=[csrf_processor, auth_user_processor],
                autoescape=False)
    setup_database(app)
    setup_redis(app)
    setup_routes(app)

    return app
