package com.example.samplegame.update;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.view.Gravity;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;

/** Lightweight same-process launcher; first-install extraction never blocks Android's UI thread. */
public final class ReleaseBootstrapActivity extends Activity {
    // Only Android's UI thread reads or writes these lifecycle/launch fields.
    private boolean resumed, ready, launched;

    @Override public void onCreate(Bundle savedInstanceState) {
        ReleaseRecovery.cancelLegacyAlarm(this);
        boolean recovery = getIntent().getBooleanExtra(ReleaseRecovery.EXTRA, false);
        if (recovery) getIntent().removeExtra("cmdline");
        super.onCreate(recovery ? null : savedInstanceState);
        if (ReleasePlayer.isLibraryLoaded()) {
            Intent existing = new Intent(); existing.setClassName(getPackageName(), "com.epicgames.unreal.GameActivity");
            existing.addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT | Intent.FLAG_ACTIVITY_SINGLE_TOP);
            startActivity(existing); finish(); return;
        }
        LinearLayout frame = new LinearLayout(this);
        frame.setOrientation(LinearLayout.VERTICAL); frame.setGravity(Gravity.CENTER);
        frame.setPadding(48, 48, 48, 48); frame.setBackgroundColor(Color.rgb(35, 40, 35));
        TextView title = new TextView(this);
        title.setText(getApplicationInfo().loadLabel(getPackageManager()));
        title.setTextSize(34);
        title.setTextColor(Color.rgb(222, 255, 0)); title.setGravity(Gravity.CENTER);
        TextView status = new TextView(this); status.setText("正在准备游戏与存档…\n首次启动可能需要稍候");
        status.setTextSize(16); status.setTextColor(Color.rgb(250, 250, 235)); status.setGravity(Gravity.CENTER);
        status.setPadding(0, 28, 0, 28);
        ProgressBar progress = new ProgressBar(this); progress.setIndeterminate(true);
        frame.addView(title); frame.addView(status); frame.addView(progress); setContentView(frame);
        Thread worker = new Thread(() -> {
            try {
                ReleasePlayer.prepareForLaunch(this);
                runOnUiThread(() -> {
                    ready = true;
                    launchWhenResumed();
                });
            } catch (Exception error) {
                runOnUiThread(() -> {
                    progress.setVisibility(android.view.View.GONE);
                    status.setText("游戏文件检查未通过。\n请完全关闭游戏后重试，或重新安装完整包。\n" + error.getClass().getSimpleName());
                });
            }
        }, "SampleGameReleasePrepare");
        worker.start();
    }

    @Override protected void onResume() {
        super.onResume();
        resumed = true;
        launchWhenResumed();
    }

    @Override protected void onPause() {
        resumed = false;
        super.onPause();
    }

    private void launchWhenResumed() {
        if (!ready || !resumed || launched || isFinishing() || isDestroyed()) return;
        launched = true;
        Intent next = new Intent(); next.setClassName(getPackageName(), "com.epicgames.unreal.SplashActivity");
        next.putExtra("cmdline", ReleasePlayer.launchArguments());
        if (getIntent().getBooleanExtra(ReleaseRecovery.EXTRA, false)) {
            // A factory-created Bootstrap may still own the old singleTask UE
            // component record. Finish it before requesting a clean UE task.
            next.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
            finish();
            getApplicationContext().startActivity(next);
        } else { startActivity(next); finish(); }
    }
}
