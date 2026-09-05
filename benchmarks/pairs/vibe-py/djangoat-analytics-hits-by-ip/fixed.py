# Provenance: Contrast-Security-OSS/DjanGoat hits_by_ip (fixed).
# repo: Contrast-Security-OSS/DjanGoat
# commit: 082c88bfefced508ae083b92b459c808f95e905e
# parent: 082c88bfefced508ae083b92b459c808f95e905e
# commit_url: https://github.com/Contrast-Security-OSS/DjanGoat/blob/082c88bfefced508ae083b92b459c808f95e905e/app/models/Analytics/analytics.py#L57
# cve: 
# license: MIT
# function: hits_by_ip
# relpath: app/models/Analytics/analytics.py
# provenance: human
# mechanism: source_reaches_sink

    def parse_field(field):
        valid_fields = ["ip_address", "referrer", "user_agent"]
        if field in valid_fields:
            return field
        else:
            return '1'
