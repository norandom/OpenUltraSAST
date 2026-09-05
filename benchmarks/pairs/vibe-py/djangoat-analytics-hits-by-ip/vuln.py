# Provenance: Contrast-Security-OSS/DjanGoat hits_by_ip (vuln).
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

    def hits_by_ip(cls, ip, col='*'):
        table_name = cls.objects.model._meta.db_table
        cmd = "SELECT %s FROM %s WHERE ip_address='%s' ORDER BY id DESC" % (
            col, table_name, ip)
        with connection.cursor() as cursor:
            cursor.execute(cmd)
            raw = cursor.fetchall()
        formatted = Analytics.format_raw_sql(cmd, raw, col)
        return formatted
