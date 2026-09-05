# Provenance: dolevf/Damn-Vulnerable-GraphQL-Application resolve_system_diagnostics (vuln).
# repo: dolevf/Damn-Vulnerable-GraphQL-Application
# commit: a961308c02d1fb462b192681c336b0739e432da7
# parent: a961308c02d1fb462b192681c336b0739e432da7
# commit_url: https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application/blob/a961308c02d1fb462b192681c336b0739e432da7/core/views.py#L345
# cve: 
# license: MIT
# function: resolve_system_diagnostics
# relpath: core/views.py
# provenance: human
# mechanism: source_reaches_sink

  def resolve_system_diagnostics(self, info, username, password, cmd='whoami'):
    q = User.query.filter_by(username='admin').first()
    real_passw = q.password
    res, msg = security.check_creds(username, password, real_passw)
    Audit.create_audit_entry(info)
    if res:
      output = f'{cmd}: command not found'
      if security.allowed_cmds(cmd):
        output = helpers.run_cmd(cmd)
      return output
    return msg
