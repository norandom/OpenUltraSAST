# Provenance: LinuxUser255/Vulnerable_Python_Apps do_GET (vuln).
# repo: LinuxUser255/Vulnerable_Python_Apps
# commit: 6336c77e6db523a5df34c4b628dff4159110797a
# parent: 6336c77e6db523a5df34c4b628dff4159110797a
# commit_url: https://github.com/LinuxUser255/Vulnerable_Python_Apps/blob/6336c77e6db523a5df34c4b628dff4159110797a/Insecure_Frameworks/bad_mvc.py#L37
# cve: 
# license: GPL-3.0
# function: do_GET
# relpath: Insecure_Frameworks/bad_mvc.py
# provenance: human
# mechanism: source_reaches_sink

    def do_GET(self):
        cookies = SimpleCookie(self.headers.get('Cookie'))
        if cookies.get('session_id'):
            try:
                username = self.decrypt(cookies.get('session_id').value) # regex and escaped all inputs
            except:
                self.send_response(500)
                return
        else:
            username = 'Anonymous'
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(bytes("Hello", "utf-8"))
        self.wfile.write(bytes("", "utf-8"))
        self.wfile.write(bytes("Hello %s" % username, "utf-8")) # needs encoding
        self.wfile.write(bytes("", "utf-8"))
