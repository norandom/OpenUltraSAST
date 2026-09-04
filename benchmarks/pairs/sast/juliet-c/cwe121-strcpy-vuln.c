/* Juliet CWE-121 flow variant 01 — bad sink only.
 * Upstream: CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_cpy_01.c
 * https://github.com/arichardson/juliet-test-suite-c (NIST Juliet 1.3, CC0)
 */
#include <string.h>

void CWE121_char_declare_cpy_01_bad(char *data, char *source)
{
    /* POTENTIAL FLAW: data may not have enough space to hold source */
    strcpy(data, source);
}
