# Provenance: dolevf/Damn-Vulnerable-GraphQL-Application resolve_pastes (vuln).
# repo: dolevf/Damn-Vulnerable-GraphQL-Application
# commit: a961308c02d1fb462b192681c336b0739e432da7
# parent: a961308c02d1fb462b192681c336b0739e432da7
# commit_url: https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application/blob/a961308c02d1fb462b192681c336b0739e432da7/core/views.py#L320
# cve: 
# license: MIT
# function: resolve_pastes
# relpath: core/views.py
# provenance: human
# mechanism: source_reaches_sink

  def resolve_pastes(self, info, public=False, limit=1000, filter=None):
    query = PasteObject.get_query(info)
    Audit.create_audit_entry(info)
    result = query.filter_by(public=public, burn=False)

    if filter:
      result = result.filter(text("title = '%s' or content = '%s'" % (filter, filter)))

    return result.order_by(Paste.id.desc()).limit(limit)
