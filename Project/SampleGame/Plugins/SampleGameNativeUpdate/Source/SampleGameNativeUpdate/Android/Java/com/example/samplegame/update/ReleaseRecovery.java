package com.example.samplegame.update;

import android.app.Activity;
import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.os.Process;
import android.os.SystemClock;
import android.util.Log;
import java.util.HashSet;

/** Cold task restoration must return through preparation before any Unreal load. */
final class ReleaseRecovery {
    static final String EXTRA = "samplegameReleaseRecovery";
    private static final int REQUEST = 0x474a106;
    private ReleaseRecovery() {}

    interface Terminator { void terminate(); }
    static Terminator terminator = () -> { Process.killProcess(Process.myPid()); System.exit(72); };

    static boolean needsBootstrap(String name) {
        return !ReleasePlayer.isPrepared() && ("com.epicgames.unreal.GameActivity".equals(name)
                || "com.epicgames.unreal.SplashActivity".equals(name));
    }

    static void clearRestoredIntent(Intent intent) {
        if (intent == null) return;
        intent.replaceExtras((Bundle) null);
        intent.setAction(null); intent.setData(null);
        if (intent.getCategories() != null) for (String category : new HashSet<>(intent.getCategories())) intent.removeCategory(category);
        intent.putExtra(EXTRA, true);
    }

    private static Intent alarmIntent(Context context) {
        Intent intent = new Intent();
        intent.setClassName(context.getPackageName(), "com.example.samplegame.update.ReleaseBootstrapActivity");
        intent.setAction(context.getPackageName() + ".SAMPLEGAME_RELEASE_RECOVERY");
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
        intent.putExtra(EXTRA, true);
        return intent;
    }

    /** Cancel only our fixed recovery token, including when the user manually reopened first. */
    static void cancelLegacyAlarm(Context context) {
        if (Build.VERSION.SDK_INT < 26 || Build.VERSION.SDK_INT > 27) return;
        PendingIntent pending = PendingIntent.getActivity(context, REQUEST, alarmIntent(context), PendingIntent.FLAG_NO_CREATE | PendingIntent.FLAG_ONE_SHOT | PendingIntent.FLAG_IMMUTABLE);
        if (pending == null) return;
        AlarmManager alarms = (AlarmManager) context.getSystemService(Context.ALARM_SERVICE);
        if (alarms == null) throw new IllegalStateException("Recovery alarm service unavailable");
        alarms.cancel(pending); pending.cancel();
        Log.i("SampleGameReleasePlayer", "SAMPLEGAME_RELEASE_RECOVERY_ALARM_CANCELLED");
    }

    /** API26/27 have no component factory. A system-owned PendingIntent survives self death. */
    static void restartLegacy(Activity activity) {
        if (Build.VERSION.SDK_INT < 26 || Build.VERSION.SDK_INT > 27 || ReleasePlayer.isPrepared() || ReleasePlayer.isLibraryLoaded())
            throw new IllegalStateException("Legacy recovery only applies before native loading on API26/27");
        AlarmManager alarms = (AlarmManager) activity.getSystemService(Context.ALARM_SERVICE);
        if (alarms == null) throw new IllegalStateException("Recovery alarm service unavailable");
        PendingIntent pending = PendingIntent.getActivity(activity, REQUEST, alarmIntent(activity),
                PendingIntent.FLAG_CANCEL_CURRENT | PendingIntent.FLAG_ONE_SHOT | PendingIntent.FLAG_IMMUTABLE);
        // Android8 clamps near-future alarms to approximately >=5 seconds. Do not
        // promise a 300ms recovery. A manual Bootstrap launch cancels this token.
        alarms.setExact(AlarmManager.ELAPSED_REALTIME, SystemClock.elapsedRealtime() + 300, pending);
        Log.i("SampleGameReleasePlayer", "SAMPLEGAME_RELEASE_LEGACY_RECOVERY_SCHEDULED sdk=" + Build.VERSION.SDK_INT);
        terminator.terminate();
        throw new IllegalStateException("Recovery process termination did not complete");
    }
}
