package android.app;
import android.content.Intent;
public class AppComponentFactory {
    public Activity instantiateActivity(ClassLoader loader,String name,Intent intent) throws InstantiationException,IllegalAccessException,ClassNotFoundException {
        return (Activity)loader.loadClass(name).newInstance();
    }
}
