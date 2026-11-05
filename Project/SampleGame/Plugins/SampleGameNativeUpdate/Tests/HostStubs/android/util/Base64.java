package android.util;
public class Base64 {
    public static final int NO_WRAP = 2;
    public static byte[] decode(String value, int flags) { return java.util.Base64.getDecoder().decode(value); }
}
