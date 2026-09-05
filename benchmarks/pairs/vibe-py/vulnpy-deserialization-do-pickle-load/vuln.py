# Provenance: Contrast-Security-OSS/vulnpy do_pickle_load (vuln).
# repo: Contrast-Security-OSS/vulnpy
# commit: d1d0f64c06f038fe59a049e0e6001bfaf9839697
# parent: d1d0f64c06f038fe59a049e0e6001bfaf9839697
# commit_url: https://github.com/Contrast-Security-OSS/vulnpy/blob/d1d0f64c06f038fe59a049e0e6001bfaf9839697/src/vulnpy/trigger/deserialization.py#L8
# cve: 
# license: MIT
# function: do_pickle_load
# relpath: src/vulnpy/trigger/deserialization.py
# provenance: human
# mechanism: source_reaches_sink

def do_pickle_load(user_input):
    user_input = io.BytesIO(user_input.encode("utf-8"))
    return pickle.load(user_input)
