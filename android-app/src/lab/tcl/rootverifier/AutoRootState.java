package lab.tcl.rootverifier;

import android.content.Context;
import android.content.SharedPreferences;

/** Persistent, fail-closed state for the opt-in, exact-profile automation. */
final class AutoRootState {
    private static final String PREFS = "auto_root_settings";
    private static final String ENABLED = "enabled";
    private static final String AUTHORIZED_PROFILE = "authorized_profile";
    private static final String PENDING_BOOT = "pending_boot";
    private static final String LAST_SUCCESS_BOOT = "last_success_boot";
    private static final String LAST_STATUS = "last_status";

    private AutoRootState() { }

    private static SharedPreferences prefs(Context context) {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    static boolean isEnabled(Context context) {
        SharedPreferences prefs = prefs(context);
        return prefs.getBoolean(ENABLED, false)
                && TclRootProfile.fromAuthorizationKey(
                        prefs.getString(AUTHORIZED_PROFILE, "")) != null;
    }

    static String authorizedProfile(Context context) {
        return prefs(context).getString(AUTHORIZED_PROFILE, "");
    }

    static boolean enableForValidatedProfile(Context context,
            TclRootProfile profile) {
        if (profile == null) return false;
        return prefs(context).edit()
                .putBoolean(ENABLED, true)
                .putString(AUTHORIZED_PROFILE, profile.authorizationKey())
                .remove(PENDING_BOOT)
                .putString(LAST_STATUS,
                        "Enabled after a validated " + profile.firmware
                                + " root session")
                .commit();
    }

    static boolean disable(Context context, String reason) {
        return prefs(context).edit()
                .putBoolean(ENABLED, false)
                .remove(AUTHORIZED_PROFILE)
                .remove(PENDING_BOOT)
                .putString(LAST_STATUS, reason)
                .commit();
    }

    static String pendingBoot(Context context) {
        return prefs(context).getString(PENDING_BOOT, "");
    }

    static String lastSuccessBoot(Context context) {
        return prefs(context).getString(LAST_SUCCESS_BOOT, "");
    }

    static String lastStatus(Context context) {
        return prefs(context).getString(LAST_STATUS, "Never run");
    }

    static boolean markAttemptStarted(Context context, String bootId) {
        return prefs(context).edit()
                .putString(PENDING_BOOT, bootId)
                .putString(LAST_STATUS, "Automatic exact-profile attempt started")
                .commit();
    }

    static void markSuccess(Context context, String bootId) {
        prefs(context).edit()
                .remove(PENDING_BOOT)
                .putString(LAST_SUCCESS_BOOT, bootId)
                .putString(LAST_STATUS,
                        "Automatic temporary root validated for boot " + bootId)
                .apply();
    }

    static void markStoppedBeforeAttempt(Context context, String status) {
        prefs(context).edit().putString(LAST_STATUS, status).apply();
    }

    static void markFailedAfterAttempt(Context context, String status) {
        /* Keep PENDING_BOOT set.  A different boot id will disarm automation,
         * preventing a panic/reboot loop. */
        prefs(context).edit().putString(LAST_STATUS, status).apply();
    }

    static boolean disarmAfterIncompletePreviousBoot(Context context,
            String currentBootId) {
        String pending = pendingBoot(context);
        if (pending.isEmpty() || pending.equals(currentBootId)) return false;
        disable(context, "Disabled: the previous automatic attempt did not "
                + "report success (boot " + pending + ")");
        return true;
    }
}
