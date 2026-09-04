/* Juliet CWE-121 goodG2B still copies with strcpy (larger buffer, same sink).
 * Regex SAST is expected to keep firing — that is the Juliet goodG2B trap.
 * Upstream: CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_cpy_01.c
 */
#include <string.h>

void CWE121_char_declare_cpy_01_goodG2B(char *data, char *source)
{
    strcpy(data, source);
}
