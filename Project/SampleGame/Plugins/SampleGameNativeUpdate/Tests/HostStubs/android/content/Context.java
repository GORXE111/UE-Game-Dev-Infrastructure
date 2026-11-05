package android.content;
import android.content.pm.PackageManager;
import android.content.pm.ApplicationInfo;
import android.content.res.AssetManager;
import java.io.File;
public class Context {
    public static final int MODE_PRIVATE = 0;
    public static final String ALARM_SERVICE = "alarm";
    public Context getApplicationContext() { return this; }
    public String getPackageName() { return "com.example.samplegame"; }
    public AssetManager getAssets() { throw new UnsupportedOperationException(); }
    public File getDir(String name, int mode) { throw new UnsupportedOperationException(); }
    public PackageManager getPackageManager() { throw new UnsupportedOperationException(); }
    public ApplicationInfo getApplicationInfo() { throw new UnsupportedOperationException(); }
    public File getFilesDir() { throw new UnsupportedOperationException(); }
    public File getExternalFilesDir(String type) { throw new UnsupportedOperationException(); }
    public Object getSystemService(String name) { throw new UnsupportedOperationException(); }
}
