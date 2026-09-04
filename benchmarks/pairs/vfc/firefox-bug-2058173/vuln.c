/* Provenance: mozilla-firefox/firefox mar_read_index (vuln).
 * repo: mozilla-firefox/firefox
 * commit: eed0931f85474d0db6e2326dfd9718c6bf1cd418
 * parent: eed0931f85474d0db6e2326dfd9718c6bf1cd418
 * commit_url: https://github.com/mozilla-firefox/firefox/commit/e46f28da1cd3a5d46a2680b3d87361e9e8de4ae6
 * cve: BUG-2058173
 * license: MPL-2.0
 * function: mar_read_index
 * relpath: modules/libmar/src/mar_read.c
 */

static int mar_read_index(MarFile* mar) {
  char id[MAR_ID_SIZE], *buf, *bufptr, *bufend;
  uint32_t offset_to_index, size_of_index;
  size_t mar_position = 0;

  /* verify MAR ID */
  if (mar_read_buffer(mar, id, &mar_position, MAR_ID_SIZE) != 0) {
    return -1;
  }
  if (memcmp(id, MAR_ID, MAR_ID_SIZE) != 0) {
    return -1;
  }

  if (mar_read_buffer(mar, &offset_to_index, &mar_position, sizeof(uint32_t)) !=
      0) {
    return -1;
  }
  offset_to_index = ntohl(offset_to_index);

  mar_position = 0;
  if (mar_buffer_seek(mar, &mar_position, offset_to_index) != 0) {
    return -1;
  }
  if (mar_read_buffer(mar, &size_of_index, &mar_position, sizeof(uint32_t)) !=
      0) {
    return -1;
  }
  size_of_index = ntohl(size_of_index);

  buf = (char*)malloc(size_of_index);
  if (!buf) {
    return -1;
  }
  if (mar_read_buffer(mar, buf, &mar_position, size_of_index) != 0) {
    free(buf);
    return -1;
  }

  bufptr = buf;
  bufend = buf + size_of_index;
  while (bufptr < bufend && mar_consume_index(mar, &bufptr, bufend) == 0);

  free(buf);
  return (bufptr == bufend) ? 0 : -1;
}
