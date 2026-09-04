#include <stdio.h>
#include <sqlite3.h>

void search(sqlite3 *db, char *term) {
  char query[512];
  snprintf(query, sizeof(query), "SELECT * FROM items WHERE title LIKE '%%%s%%'", term);
  sqlite3_exec(db, query, 0, 0, 0); /* CWE-89 split-sink: query built on prior line (regex blind spot) */
}
