# Provenance: Contrast-Security-OSS/vulnpy do_subprocess_popen (vuln).
# repo: Contrast-Security-OSS/vulnpy
# commit: d1d0f64c06f038fe59a049e0e6001bfaf9839697
# parent: d1d0f64c06f038fe59a049e0e6001bfaf9839697
# commit_url: https://github.com/Contrast-Security-OSS/vulnpy/blob/d1d0f64c06f038fe59a049e0e6001bfaf9839697/src/vulnpy/trigger/cmdi.py#L10
# cve: 
# license: MIT
# function: do_subprocess_popen
# relpath: src/vulnpy/trigger/cmdi.py
# provenance: human
# mechanism: source_reaches_sink

def do_subprocess_popen(command):
    process = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True
    )
    stdout, _ = process.communicate()
    return stdout
