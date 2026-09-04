/* Juliet CWE-78 flow variant 01 — bad sink only.
 * Upstream: CWE78_OS_Command_Injection__console_readLine_01.java
 * https://github.com/UnitTestBot/juliet-java-test-suite (NIST Juliet 1.3, CC0)
 */
public class CWE78_OS_Command_Injection__console_readLine_01 {
    public void bad(String data) throws Throwable {
        String osCommand = "/bin/ls ";
        Process process = Runtime.getRuntime().exec(osCommand + data);
        process.waitFor();
    }
}
