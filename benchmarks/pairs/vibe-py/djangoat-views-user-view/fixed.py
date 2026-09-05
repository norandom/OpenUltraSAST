# Provenance: Contrast-Security-OSS/DjanGoat user_view (fixed).
# repo: Contrast-Security-OSS/DjanGoat
# commit: 082c88bfefced508ae083b92b459c808f95e905e
# parent: 082c88bfefced508ae083b92b459c808f95e905e
# commit_url: https://github.com/Contrast-Security-OSS/DjanGoat/blob/082c88bfefced508ae083b92b459c808f95e905e/app/views/users/views.py#L74
# cve: 
# license: MIT
# function: user_view
# relpath: app/views/users/views.py
# provenance: human
# mechanism: source_reaches_sink

    def parse_field(field):
        valid_fields = ["ip_address", "referrer", "user_agent"]
        if field in valid_fields:
            return field
        else:
            return '1'
