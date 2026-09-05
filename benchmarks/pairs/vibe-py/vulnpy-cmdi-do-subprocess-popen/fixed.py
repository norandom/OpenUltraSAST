# Provenance: Contrast-Security-OSS/vulnpy do_subprocess_popen (fixed).
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

def _execute(db_func):
    try:
        db_connection = _db_reset()
        cursor = db_connection.cursor()
        db_func(cursor)
        all_rows = cursor.execute(SELECT_ALL)
        return ";".join([",".join(row) for row in all_rows])
    except Exception:
        return "error"
