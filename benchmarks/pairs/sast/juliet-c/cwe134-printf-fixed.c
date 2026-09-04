/* Juliet CWE-134 flow variant 01 — goodB2G sink only.
 * Upstream: CWE134_Uncontrolled_Format_String__char_console_printf_01.c
 * https://github.com/arichardson/juliet-test-suite-c (NIST Juliet 1.3, CC0)
 */
#include <stdio.h>

void CWE134_char_console_printf_01_goodB2G(char *data)
{
    /* FIX: Specify the format disallowing a format string vulnerability */
    printf("%s\n", data);
}
