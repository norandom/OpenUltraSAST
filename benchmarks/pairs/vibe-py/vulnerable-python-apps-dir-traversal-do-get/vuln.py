# Provenance: LinuxUser255/Vulnerable_Python_Apps do_GET (vuln).
# repo: LinuxUser255/Vulnerable_Python_Apps
# commit: 6336c77e6db523a5df34c4b628dff4159110797a
# parent: 6336c77e6db523a5df34c4b628dff4159110797a
# commit_url: https://github.com/LinuxUser255/Vulnerable_Python_Apps/blob/6336c77e6db523a5df34c4b628dff4159110797a/Directory_Traversal/Dir_Traversal.py#L22
# cve: 
# license: GPL-3.0
# function: do_GET
# relpath: Directory_Traversal/Dir_Traversal.py
# provenance: human
# mechanism: path_join_user_input

    def do_GET(self): # no data type receive defined
        path = os.getcwd() # dir traversal and possible LFI
        pattern = r'/\.\.\/\.\.\/' # weak regex pattern
        if re.match(pattern, self.path): # escape characters needed
            self.send_response(404)
            return
        path += self.path
        if path.endswith('/'):
            path += 'index.html'
        print(path)
        if exists(path):
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(open(path).read().encode('utf-8')) # path is open no string mod
        else:
            self.send_response(404)
