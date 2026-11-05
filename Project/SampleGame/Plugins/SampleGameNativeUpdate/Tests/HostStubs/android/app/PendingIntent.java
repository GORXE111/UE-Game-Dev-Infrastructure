package android.app;
import android.content.Context;
import android.content.Intent;
import java.util.HashMap;
public class PendingIntent {
    public static final int FLAG_ONE_SHOT=0x40000000, FLAG_NO_CREATE=0x20000000, FLAG_CANCEL_CURRENT=0x10000000, FLAG_IMMUTABLE=0x4000000;
    private static final HashMap<String,PendingIntent> tokens=new HashMap<>();
    public final Intent intent; public final int flags; private final String key;
    private PendingIntent(String key,Intent intent,int flags){this.key=key;this.intent=intent;this.flags=flags;}
    public static PendingIntent getActivity(Context context,int request,Intent intent,int flags){
        String key=request+":"+intent.componentForHostTest()+":"+intent.getAction()+":"+(flags&(FLAG_ONE_SHOT|FLAG_IMMUTABLE));
        PendingIntent old=tokens.get(key);
        if((flags&FLAG_NO_CREATE)!=0)return old;
        if((flags&FLAG_CANCEL_CURRENT)!=0&&old!=null)old.cancel();
        if(old!=null&&(flags&FLAG_CANCEL_CURRENT)==0)return old;
        PendingIntent result=new PendingIntent(key,intent,flags);tokens.put(key,result);return result;
    }
    public void cancel(){tokens.remove(key);}
}
