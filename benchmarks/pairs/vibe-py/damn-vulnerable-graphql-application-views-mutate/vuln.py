# Provenance: dolevf/Damn-Vulnerable-GraphQL-Application mutate (vuln).
# repo: dolevf/Damn-Vulnerable-GraphQL-Application
# commit: a961308c02d1fb462b192681c336b0739e432da7
# parent: a961308c02d1fb462b192681c336b0739e432da7
# commit_url: https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application/blob/a961308c02d1fb462b192681c336b0739e432da7/core/views.py#L211
# cve: 
# license: MIT
# function: mutate
# relpath: core/views.py
# provenance: human
# mechanism: source_reaches_sink

  def mutate(self, info, host='pastebin.com', port=443, path='/', scheme="http"):
    url = security.strip_dangerous_characters(f"{scheme}://{host}:{port}{path}")
    cmd = helpers.run_cmd(f'curl --insecure {url}')

    owner = Owner.query.filter_by(name='DVGAUser').first()
    Paste.create_paste(
        title='Imported Paste from URL - {}'.format(helpers.generate_uuid()),
        content=cmd, public=False, burn=False,
        owner_id=owner.id, owner=owner, ip_addr=request.remote_addr,
        user_agent=request.headers.get('User-Agent', '')
    )

    Audit.create_audit_entry(info)

    return ImportPaste(result=cmd)
