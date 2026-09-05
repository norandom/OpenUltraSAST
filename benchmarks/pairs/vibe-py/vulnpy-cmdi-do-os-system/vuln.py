# Provenance: Contrast-Security-OSS/vulnpy do_os_system (vuln).
# repo: Contrast-Security-OSS/vulnpy
# commit: d1d0f64c06f038fe59a049e0e6001bfaf9839697
# parent: d1d0f64c06f038fe59a049e0e6001bfaf9839697
# commit_url: https://github.com/Contrast-Security-OSS/vulnpy/blob/d1d0f64c06f038fe59a049e0e6001bfaf9839697/src/vulnpy/trigger/cmdi.py#L6
# cve: 
# license: MIT
# function: do_os_system
# relpath: src/vulnpy/trigger/cmdi.py
# provenance: human
# mechanism: source_reaches_sink

def do_os_system(command):
    return os.system(command)
