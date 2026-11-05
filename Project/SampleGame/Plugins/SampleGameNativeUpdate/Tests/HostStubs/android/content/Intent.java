package android.content;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import android.os.Bundle;
import android.net.Uri;
public class Intent {
    public static final int FLAG_ACTIVITY_NEW_TASK=0x10000000, FLAG_ACTIVITY_CLEAR_TASK=0x8000, FLAG_ACTIVITY_REORDER_TO_FRONT=0x20000, FLAG_ACTIVITY_SINGLE_TOP=0x20000000;
    private final HashMap<String, Object> extras = new HashMap<>();
    private String action, component;
    private int flags;
    private final Set<String> categories = new HashSet<>();
    public Intent putExtra(String name, String value) { extras.put(name, value); return this; }
    public Intent putExtra(String name, boolean value) { extras.put(name,value); return this; }
    public String getStringExtra(String name) { Object value=extras.get(name); return value instanceof String?(String)value:null; }
    public boolean getBooleanExtra(String name,boolean fallback){Object value=extras.get(name);return value instanceof Boolean?(Boolean)value:fallback;}
    public Intent replaceExtras(Bundle value){extras.clear();return this;}
    public void removeExtra(String name){extras.remove(name);}
    public Intent setAction(String value){action=value;return this;}
    public String getAction(){return action;}
    public Intent setData(Uri value){return this;}
    public Set<String> getCategories(){return categories.isEmpty()?null:new HashSet<>(categories);}
    public Intent addCategory(String value){categories.add(value);return this;}
    public void removeCategory(String value){categories.remove(value);}
    public Intent setClassName(String owner,String name){component=owner+"/"+name;return this;}
    public String componentForHostTest(){return component;}
    public Intent addFlags(int value){flags|=value;return this;}
    public int getFlags(){return flags;}
}
