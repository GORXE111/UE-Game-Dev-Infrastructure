package android.os;
public class Process {
    public static int myPid() { return 12345; }
    public static void killProcess(int pid) { throw new AssertionError("A host test must not terminate an actual process"); }
}
