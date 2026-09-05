/* Juliet 1.3 CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_cpy_01 (CC0).
 * bad(): data points at a 10-byte buffer; strcpy writes 11 bytes (10 chars + NUL). */
#include <string.h>
#define SRC_STRING "AAAAAAAAAA"

void CWE121_char_declare_cpy_01_bad()
{
    char * data;
    char dataBadBuffer[10];
    char dataGoodBuffer[10+1];
    /* FLAW: Set a pointer to a buffer that does not leave room for a NULL terminator */
    data = dataBadBuffer;
    data[0] = '\0'; /* null terminate */
    {
        char source[10+1] = SRC_STRING;
        strcpy(data, source);
    }
}
