package android.app;
import android.content.Context;
import android.content.Intent;
public class Activity extends Context {
    private final Intent intent = new Intent();
    public Intent getIntent() { return intent; }
}
