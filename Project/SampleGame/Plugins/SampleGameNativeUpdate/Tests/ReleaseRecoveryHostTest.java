package com.example.samplegame.update;

import android.app.Activity;
import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.os.Build;
import java.lang.reflect.Field;

/** Policy and system-token API doubles, never a real task/AlarmManager/Recents acceptance. */
public final class ReleaseRecoveryHostTest {
    private static int checks,nativeLoads,terminations;
    private static void check(boolean value,String message){++checks;if(!value)throw new AssertionError(message);}
    private static void field(String name,Object value)throws Exception{Field f=ReleasePlayer.class.getDeclaredField(name);f.setAccessible(true);f.set(null,value);}
    private static final class Terminated extends Error{}
    private static final class LegacyActivity extends Activity {
        final AlarmManager alarms=new AlarmManager();
        @Override public Object getSystemService(String name){return alarms;}
    }
    private static Intent stale(){return new Intent().putExtra("cmdline","-UserDir=/old -SampleGameReleaseTicket=/old/ticket.json -SampleGameMenuProbe")
            .putExtra("oldState","must-disappear").setAction("android.intent.action.MAIN").addCategory("android.intent.category.LAUNCHER");}

    public static void main(String[] args)throws Exception{
        ReleaseComponentFactory factory=new ReleaseComponentFactory();ClassLoader loader=ReleaseRecoveryHostTest.class.getClassLoader();
        Build.VERSION.SDK_INT=36;field("prepared",false);
        for(String name:new String[]{"com.epicgames.unreal.GameActivity","com.epicgames.unreal.SplashActivity"}){
            Intent old=stale();Activity actual=factory.instantiateActivity(loader,name,old);
            check(actual instanceof ReleaseBootstrapActivity,"Cold UE restore instantiates only plain bootstrap before NativeActivity onCreate");
            check(old.getStringExtra("cmdline")==null&&old.getStringExtra("oldState")==null,"Recovery discards stale ticket/save/QA extras");
            check(old.getBooleanExtra(ReleaseRecovery.EXTRA,false)&&old.getAction()==null&&old.getCategories()==null,"Recovery is explicit and has no stale MAIN/LAUNCHER redirect");
        }
        Activity ordinary=factory.instantiateActivity(loader,"android.app.Activity",new Intent());
        check(ordinary.getClass()==Activity.class,"Unrelated activities retain inherited AndroidX factory behavior");
        field("prepared",true);
        Activity real=factory.instantiateActivity(loader,"com.epicgames.unreal.GameActivity",stale());
        check(real.getClass().getName().equals("com.epicgames.unreal.GameActivity"),"Prepared launch instantiates genuine UE activity through inherited factory");
        check(ReleasePlayer.isPrepared(),"Factory does not mutate or replace the existing prepared selection");

        for(int sdk:new int[]{26,27}){
            Build.VERSION.SDK_INT=sdk;field("prepared",false);field("preparationAttempted",false);field("loadAttempted",false);field("libraryLoaded",false);
            LegacyActivity activity=new LegacyActivity();activity.getIntent().putExtra("cmdline","-UserDir=/stale -pakdir=/old");
            ReleasePlayer.libraryLoader=(cl,file)->{nativeLoads++;};
            ReleaseRecovery.terminator=()->{terminations++;throw new Terminated();};
            boolean stopped=false;try{ReleasePlayer.loadUnreal(activity,loader);}catch(Terminated expected){stopped=true;}
            check(stopped&&activity.alarms.scheduleCount==1,"API26/27 schedules a system-owned restart then ends only the unprepared process");
            check(nativeLoads==0,"Legacy cold restore never tries any candidate or APK native library");
            PendingIntent pending=activity.alarms.lastScheduled;Intent next=pending.intent;
            check(next.componentForHostTest().endsWith("/com.example.samplegame.update.ReleaseBootstrapActivity")&&next.getStringExtra("cmdline")==null,
                    "Legacy system token targets bootstrap and cannot replay stale native/save/QA routing");
            check((next.getFlags()&(Intent.FLAG_ACTIVITY_NEW_TASK|Intent.FLAG_ACTIVITY_CLEAR_TASK))==(Intent.FLAG_ACTIVITY_NEW_TASK|Intent.FLAG_ACTIVITY_CLEAR_TASK),
                    "Legacy handoff discards the stale task activity instead of reusing its singleTask record");
            check((pending.flags&PendingIntent.FLAG_ONE_SHOT)!=0&&(pending.flags&PendingIntent.FLAG_IMMUTABLE)!=0,
                    "Recovery token is explicit, one-shot and immutable");
            check(activity.alarms.type==AlarmManager.ELAPSED_REALTIME&&activity.alarms.at>0,"Recovery uses a monotonic alarm without requesting new exact-alarm permission");
            ReleaseRecovery.cancelLegacyAlarm(activity);
            check(activity.alarms.lastCancelled==pending,"A manual bootstrap launch cancels the exact outstanding legacy recovery alarm");
            activity.alarms.lastCancelled=null;ReleaseRecovery.cancelLegacyAlarm(activity);
            check(activity.alarms.lastCancelled==null,"A consumed/cancelled one-shot token is safely absent");
            boolean refused=false;try{ReleasePlayer.loadUnreal(activity,loader);}catch(IllegalStateException expected){refused=true;}
            check(refused&&activity.alarms.scheduleCount==1,"A failed same-process restore cannot schedule repeated handoffs or load twice");
        }
        Build.VERSION.SDK_INT=36;field("prepared",false);field("preparationAttempted",false);field("loadAttempted",false);field("libraryLoaded",false);
        LegacyActivity modern=new LegacyActivity();boolean rejected=false;
        try{ReleasePlayer.loadUnreal(modern,loader);}catch(IllegalStateException expected){rejected=true;}
        check(rejected&&modern.alarms.scheduleCount==0,"API28+ cannot silently invoke legacy alarms if a required factory routing step was bypassed");
        check(terminations==2&&nativeLoads==0,"Only the two explicitly simulated legacy self-terminations occurred");
        System.out.println("SAMPLEGAME_RELEASE_RECOVERY_HOST_OK checks="+checks+" factory=host-double alarm=host-double actualTaskRestorationValidated=false");
    }
}
