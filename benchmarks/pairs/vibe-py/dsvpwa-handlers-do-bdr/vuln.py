# Provenance: sgabe/DSVPWA do_BDR (vuln).
# repo: sgabe/DSVPWA
# commit: a06abb306ed3699bb2f073e3f41d3d9c57012819
# parent: a06abb306ed3699bb2f073e3f41d3d9c57012819
# commit_url: https://github.com/sgabe/DSVPWA/blob/a06abb306ed3699bb2f073e3f41d3d9c57012819/dsvpwa/handlers.py#L183
# cve: 
# license: MIT
# function: do_BDR
# relpath: dsvpwa/handlers.py
# provenance: human
# mechanism: source_reaches_sink

    def do_BDR(self):
        if self.risk < 3:
            self.send_response(HTTPStatus.BAD_REQUEST)
            content = dsvpwa.attacks.Attack.warning.format(self.risk).encode()
        else:
            self.send_response(HTTPStatus.OK)
            content = subprocess.check_output(
                self.path[1:],
                shell=True,
                stderr=subprocess.STDOUT,
                stdin=subprocess.PIPE
            )

        self.send_header('Content-type', 'text/plain')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(content)
        self.wfile.flush()
