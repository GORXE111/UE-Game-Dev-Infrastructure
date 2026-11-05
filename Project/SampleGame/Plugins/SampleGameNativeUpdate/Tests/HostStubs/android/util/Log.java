package android.util;
public class Log {
    public static int i(String tag, String text) { System.out.println(tag + ": " + text); return 0; }
    public static int w(String tag, String text) { System.out.println(tag + ": " + text); return 0; }
    public static int w(String tag, String text, Throwable error) { return w(tag, text + ": " + error); }
}
