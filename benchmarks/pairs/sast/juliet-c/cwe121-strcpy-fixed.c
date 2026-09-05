/* Juliet 1.3 CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_cpy_01 (CC0).
 * goodG2B(): same strcpy; data points at the 11-byte buffer, so the copy fits. */
#include <string.h>
#define SRC_STRING "AAAAAAAAAA"

static void CWE121_char_declare_cpy_01_goodG2B()
{
    char * data;
    char dataBadBuffer[10];
    char dataGoodBuffer[10+1];
    /* FIX: Set a pointer to a buffer that leaves room for a NULL terminator */
    data = dataGoodBuffer;
    data[0] = '\0'; /* null terminate */
    {
        char source[10+1] = SRC_STRING;
        strcpy(data, source);
    }
}
