/* Juliet CWE-78 goodG2B — hardcoded source, same Runtime.exec sink.
 * Regex SAST is expected to keep firing — Juliet goodG2B trap.
 * Upstream: CWE78_OS_Command_Injection__console_readLine_01.java
 */
public class CWE78_OS_Command_Injection__console_readLine_01 {
    public void goodG2B() throws Throwable {
        String data = "foo";
        String osCommand = "/bin/ls ";
        Process process = Runtime.getRuntime().exec(osCommand + data);
        process.waitFor();
    }
}
