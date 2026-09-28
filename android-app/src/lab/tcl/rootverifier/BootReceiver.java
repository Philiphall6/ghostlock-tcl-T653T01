package lab.tcl.rootverifier;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.util.Log;

/** Starts the opt-in foreground worker after Android has completed booting. */
public final class BootReceiver extends BroadcastReceiver {
    private static final String TAG = "TclAutoRootReceiver";

    @Override
    public void onReceive(Context context, Intent intent) {
        if (!Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())
                || !AutoRootState.isEnabled(context)) return;

        Intent service = new Intent(context, AutoRootService.class);
        service.setAction(AutoRootService.ACTION_BOOT_AUTO_ROOT);
        try {
            if (Build.VERSION.SDK_INT >= 26)
                context.startForegroundService(service);
            else
                context.startService(service);
        } catch (RuntimeException failure) {
            AutoRootState.markStoppedBeforeAttempt(context,
                    "Boot worker could not start: "
                            + failure.getClass().getSimpleName());
            Log.e(TAG, "Unable to start automatic-root worker", failure);
        }
    }
}
