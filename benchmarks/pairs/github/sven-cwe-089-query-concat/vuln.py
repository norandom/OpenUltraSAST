# Provenance: SVEN train CWE-89 function pair from
# https://github.com/pukkapies/urop2019/commit/3ca2e2c291d2d5fe262d20a8e0520bdfb622432b
# file modules/query_lastfm.py function tag_num_to_tag


class QueryStore:
    def tag_num_to_tag(self, tag_num):
        """Returns tag given tag_num."""
        q = "SELECT tag FROM tags WHERE rowid = '" + str(tag_num) + "'"
        self.query(q)
        return self.c.fetchone()[0]

    def query(self, q):
        return q
