/* Juliet CWE-134 flow variant 01 — bad sink only.
 * Upstream: testcases/CWE134_Uncontrolled_Format_String/s01/
 *   CWE134_Uncontrolled_Format_String__char_console_printf_01.c
 * https://github.com/arichardson/juliet-test-suite-c (NIST Juliet 1.3, CC0)
 */
#include <stdio.h>

void CWE134_char_console_printf_01_bad(char *data)
{
    /* POTENTIAL FLAW: Do not specify the format allowing a format string vulnerability */
    printf(data);
}
