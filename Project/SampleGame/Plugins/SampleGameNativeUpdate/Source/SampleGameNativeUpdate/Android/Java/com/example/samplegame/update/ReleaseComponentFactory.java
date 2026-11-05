package com.example.samplegame.update;

import android.app.Activity;
import android.content.Intent;
import android.util.Log;
import androidx.core.app.CoreComponentFactory;

/** Preserve AndroidX instantiation for all ordinary components and prepared UE starts. */
public final class ReleaseComponentFactory extends CoreComponentFactory {
    @Override public Activity instantiateActivity(ClassLoader loader, String name, Intent intent)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        if (ReleaseRecovery.needsBootstrap(name)) {
            ReleaseRecovery.clearRestoredIntent(intent);
            Log.i("SampleGameReleasePlayer", "SAMPLEGAME_RELEASE_COLD_ACTIVITY_REDIRECT component=" + name);
            return new ReleaseBootstrapActivity();
        }
        return super.instantiateActivity(loader, name, intent);
    }
}
