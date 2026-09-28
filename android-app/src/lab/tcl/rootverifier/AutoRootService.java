package lab.tcl.rootverifier;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.IBinder;
import android.os.SystemClock;
import android.provider.Settings;
import android.util.Base64;
import android.util.Log;

import com.tananaev.adblib.AdbConnection;
import com.tananaev.adblib.AdbCrypto;
import com.tananaev.adblib.AdbStream;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Opt-in exact-profile boot worker.  V643 is hardware validated; V637 and
 * V65x can only be armed after a successful manual session and an explicit
 * warning.  Every profile keeps independent firmware, kernel, policy and
 * payload-integrity gates.
 */
public final class AutoRootService extends Service {
    static final String ACTION_BOOT_AUTO_ROOT =
            "lab.tcl.rootverifier.action.BOOT_AUTO_ROOT";

    private static final String TAG = "TclAutoRootService";
    private static final String CHANNEL_ID = "tcl_auto_root";
    private static final int NOTIFICATION_ID = 643;
    private static final AtomicBoolean RUNNING = new AtomicBoolean(false);

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        startForeground(NOTIFICATION_ID,
                notification(getString(R.string.auto_root_notification_waiting), true));

        if (intent == null
                || !ACTION_BOOT_AUTO_ROOT.equals(intent.getAction())
                || !AutoRootState.isEnabled(this)) {
            finishWorker(getString(R.string.auto_root_notification_disabled), false);
            return START_NOT_STICKY;
        }
        if (!RUNNING.compareAndSet(false, true)) return START_NOT_STICKY;

        new Thread(() -> {
            String bootId = AutoRootRunner.currentBootSessionId(this);
            try {
                if (!AutoRootRunner.validBootSessionId(bootId)) {
                    AutoRootState.markStoppedBeforeAttempt(this,
                            "Automatic root stopped: boot identifier unavailable");
                    finishWorker(getString(
                            R.string.auto_root_notification_preflight_refused), false);
                    return;
                }
                if (AutoRootState.disarmAfterIncompletePreviousBoot(this, bootId)) {
                    audit("AUTO_ROOT_DISARMED previous_attempt_incomplete");
                    finishWorker(getString(
                            R.string.auto_root_notification_safety_disabled), false);
                    return;
                }
                if (bootId.equals(AutoRootState.pendingBoot(this))) {
                    audit("AUTO_ROOT_DUPLICATE_BLOCKED boot=" + bootId);
                    finishWorker(getString(
                            R.string.auto_root_notification_already_attempted), false);
                    return;
                }

                updateNotification(getString(
                        R.string.auto_root_notification_preflight), true);
                TclRootProfile profile = TclRootProfile.fromAuthorizationKey(
                        AutoRootState.authorizedProfile(this));
                if (profile == null) {
                    AutoRootState.disable(this,
                            "Disabled: authorized profile is no longer supported");
                    finishWorker(getString(
                            R.string.auto_root_notification_preflight_refused), false);
                    return;
                }
                AutoRootRunner runner = new AutoRootRunner(this, profile);
                AutoRootRunner.Outcome outcome = runner.run(bootId);
                if (outcome.success) {
                    AutoRootState.markSuccess(this, bootId);
                    audit("AUTO_ROOT_SUCCESS boot=" + bootId);
                    finishWorker(getString(
                            R.string.auto_root_notification_success), false);
                } else if (outcome.attempted) {
                    AutoRootState.markFailedAfterAttempt(this,
                            "Automatic root did not validate: "
                                    + tail(outcome.report, 500));
                    audit("AUTO_ROOT_FAILED_AFTER_ATTEMPT "
                            + oneLine(tail(outcome.report, 1000)));
                    finishWorker(getString(
                            R.string.auto_root_notification_failed_disarm_next), false);
                } else {
                    AutoRootState.markStoppedBeforeAttempt(this,
                            "Automatic root stopped before exploit: "
                                    + tail(outcome.report, 500));
                    audit("AUTO_ROOT_PREFLIGHT_REFUSED "
                            + oneLine(tail(outcome.report, 1000)));
                    finishWorker(getString(
                            R.string.auto_root_notification_preflight_refused), false);
                }
            } catch (Throwable failure) {
                AutoRootState.markFailedAfterAttempt(this,
                        "Automatic-root worker exception: "
                                + failure.getClass().getSimpleName());
                audit("AUTO_ROOT_EXCEPTION " + failure.getClass().getSimpleName()
                        + " " + String.valueOf(failure.getMessage()));
                Log.e(TAG, "Automatic-root worker failed", failure);
                finishWorker(getString(
                        R.string.auto_root_notification_failed_disarm_next), false);
            } finally {
                RUNNING.set(false);
            }
        }, "tcl-auto-root").start();
        return START_NOT_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT < 26) return;
        NotificationChannel channel = new NotificationChannel(CHANNEL_ID,
                getString(R.string.auto_root_channel),
                NotificationManager.IMPORTANCE_LOW);
        channel.setDescription(getString(R.string.auto_root_channel_description));
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager != null) manager.createNotificationChannel(channel);
    }

    private Notification notification(String text, boolean ongoing) {
        Intent open = new Intent(this, MainActivity.class);
        open.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK
                | Intent.FLAG_ACTIVITY_SINGLE_TOP);
        PendingIntent pending = PendingIntent.getActivity(this, 0, open,
                PendingIntent.FLAG_UPDATE_CURRENT
                        | (Build.VERSION.SDK_INT >= 23
                                ? PendingIntent.FLAG_IMMUTABLE : 0));
        Notification.Builder builder = Build.VERSION.SDK_INT >= 26
                ? new Notification.Builder(this, CHANNEL_ID)
                : new Notification.Builder(this);
        return builder
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setContentTitle(getString(R.string.auto_root_notification_title))
                .setContentText(text)
                .setContentIntent(pending)
                .setOngoing(ongoing)
                .setAutoCancel(!ongoing)
                .setCategory(Notification.CATEGORY_SERVICE)
                .build();
    }

    private void updateNotification(String text, boolean ongoing) {
        NotificationManager manager =
                (NotificationManager)getSystemService(NOTIFICATION_SERVICE);
        if (manager != null)
            manager.notify(NOTIFICATION_ID, notification(text, ongoing));
    }

    private void finishWorker(String text, boolean removeNotification) {
        updateNotification(text, false);
        if (Build.VERSION.SDK_INT >= 24)
            stopForeground(removeNotification
                    ? STOP_FOREGROUND_REMOVE : STOP_FOREGROUND_DETACH);
        else
            stopForeground(removeNotification);
        stopSelf();
    }

    private void audit(String event) {
        File log = new File(getFilesDir(), "root-session-audit.log");
        String line = System.currentTimeMillis() + " " + event + "\n";
        try (FileOutputStream out = new FileOutputStream(log, true)) {
            out.write(line.getBytes(StandardCharsets.UTF_8));
            out.flush();
        } catch (Exception failure) {
            Log.e(TAG, "Audit write failed", failure);
        }
    }

    private static String tail(String value, int limit) {
        if (value == null) return "null";
        return value.length() <= limit
                ? value : value.substring(value.length() - limit);
    }

    private static String oneLine(String value) {
        return value.replace('\n', ' ').replace('\r', ' ');
    }

    /** Headless copy of the exact manual route for the authorized profile. */
    private static final class AutoRootRunner {
        private static final String RESUKISU_PACKAGE =
                "com.philiphall6.resukisu.tcl";
        private static final String MCAST_HELPER_SHA256 =
                "4ca5692192b0a7598243f5070adf1e676ccd943aad4a292579ea69d38bbf1019";
        private static final String RESUKISU_KSUD32_SHA256 =
                "528c80259613a1e27a90d8f202fda33ecceba9c1fd42e1d807fdbbc859af5e68";
        private static final String ROOT_ATTEMPT_PREFS = "root_attempt_gate";
        private static final String ROOT_ATTEMPT_BOOT_ID = "consumed_boot_id";
        private static final String GHOST_PID_FILE =
                "/data/local/tmp/.tcl_root_verifier_ghost.pid";

        private final Context context;
        private final TclRootProfile profile;

        AutoRootRunner(Context context, TclRootProfile profile) {
            this.context = context.getApplicationContext();
            this.profile = profile;
        }

        static final class Outcome {
            final boolean attempted;
            final boolean success;
            final String report;

            Outcome(boolean attempted, boolean success, String report) {
                this.attempted = attempted;
                this.success = success;
                this.report = report;
            }
        }

        Outcome run(String bootId) {
            String adb = waitForLocalAdb();
            if (!adb.contains("ADB_LOCAL_OK"))
                return new Outcome(false, false,
                        "Local ADB unavailable after boot\n" + adb);

            String bundle = validateBundle();
            if (bundle != null)
                return new Outcome(false, false, bundle);

            String refusal = validateRootStartPreconditions();
            if (refusal != null)
                return new Outcome(false, false, refusal);

            String gateFailure = consumeRootAttemptForCurrentBoot(bootId);
            if (gateFailure != null)
                return new Outcome(false, false, gateFailure);

            if (!AutoRootState.markAttemptStarted(context, bootId))
                return new Outcome(false, false,
                        "Unable to persist the automatic-root safety latch");

            String report = runGhostLockViaLocalAdb(bootId);
            return new Outcome(true,
                    report.contains("TCL_DIRECT_RESUKISU_READY"), report);
        }

        private String waitForLocalAdb() {
            String last = "ADB_LOCAL_NOT_READY";
            for (int attempt = 1; attempt <= 12; attempt++) {
                last = runLocalAdbShell(
                        "echo BOOT=$(getprop sys.boot_completed); "
                                + "echo ADB_LOCAL_OK", 20);
                if (last.contains("BOOT=1") && last.contains("ADB_LOCAL_OK"))
                    return last;
                SystemClock.sleep(5000);
            }
            return last;
        }

        private String validateBundle() {
            try {
                context.getPackageManager().getPackageInfo(
                        RESUKISU_PACKAGE, PackageManager.GET_META_DATA);
            } catch (PackageManager.NameNotFoundException missing) {
                return "Required TCL ReSukiSU manager is not installed";
            }
            File nativeDir = new File(context.getApplicationInfo().nativeLibraryDir);
            File ghost = profile.ghost(nativeDir);
            File helper = new File(nativeDir, "libtclmcast.so");
            File handoff = profile.handoff(nativeDir);
            File preflight = profile.preflight(nativeDir);
            File ksud = new File(nativeDir, "libresukisuksud.so");
            File module = profile.module(nativeDir);
            if (!profile.ghostSha256.equals(sha256(ghost))
                    || !MCAST_HELPER_SHA256.equals(sha256(helper))
                    || !profile.handoffSha256.equals(sha256(handoff))
                    || !profile.preflightSha256.equals(sha256(preflight))
                    || !RESUKISU_KSUD32_SHA256.equals(sha256(ksud))
                    || !profile.moduleSha256.equals(sha256(module)))
                return "Embedded " + profile.id
                        + " payload integrity check failed";
            return null;
        }

        private String validateRootStartPreconditions() {
            String probe = runLocalAdbShell(
                    "caps=$(for cap in network_peer_controls open_perms "
                    + "extended_socket_class always_check_network cgroup_seclabel "
                    + "nnp_nosuid_transition genfs_seclabel_symlinks "
                    + "ioctl_skip_cloexec; do cat "
                    + "\"/sys/fs/selinux/policy_capabilities/$cap\" "
                    + "2>/dev/null || printf '?'; done | tr -d '\\r\\n'); "
                    + "printf 'STATE=%s|%s|%s|%s|%s|%s|%s|%s\\n' "
                    + "\"$(getprop ro.software.version_id)\" "
                    + "\"$(uname -r)\" "
                    + "\"$(getprop ro.build.version.release)\" "
                    + "\"$(getprop sys.boot_completed)\" "
                    + "\"$(getprop ro.boot.verifiedbootstate)\" "
                    + "\"$(getprop ro.boot.vbmeta.device_state)\" "
                    + "\"$(getprop ro.boot.veritymode)\" \"$(getenforce)\"; "
                    + "printf 'UPTIME='; cut -d. -f1 /proc/uptime; "
                    + "printf 'POLICY_SHA='; sha256sum "
                    + "/vendor/etc/selinux/precompiled_sepolicy | cut -d' ' -f1; "
                    + "printf 'POLICY_SIZE='; wc -c < "
                    + "/vendor/etc/selinux/precompiled_sepolicy | tr -d ' '; "
                    + "printf 'POLICYCAPS=%s\\n' \"$caps\"; "
                    + "printf 'MODULES='; grep -Ec "
                    + "'^(kernelsu|resukisu|kowsu) ' /proc/modules "
                    + "2>/dev/null || true", 45);

            String state = lineValue(probe, "STATE");
            String uptimeText = lineValue(probe, "UPTIME");
            String policyHash = lineValue(probe, "POLICY_SHA");
            String policySize = lineValue(probe, "POLICY_SIZE");
            String policyCaps = lineValue(probe, "POLICYCAPS");
            String modules = lineValue(probe, "MODULES");
            long uptime;
            try {
                uptime = Long.parseLong(uptimeText);
            } catch (RuntimeException malformed) {
                return "Unable to read uptime; no automatic attempt started\n"
                        + probe;
            }
            TclRootProfile detected = TclRootProfile.exact(
                    state, policyHash, policySize);
            if (detected == null || !profile.id.equals(detected.id))
                return "Live profile does not match the authorized exact profile "
                        + profile.firmware + "\n" + probe;
            if (uptime > 900)
                return "Boot is not fresh (uptime=" + uptime
                        + " s); no automatic attempt started";
            if (!TclRootProfile.POLICY_CAPS.equals(policyCaps))
                return "SELinux policy capabilities are altered; no attempt started";
            if (!"0".equals(modules))
                return "A root module is already loaded; no attempt started";
            return null;
        }

        private String consumeRootAttemptForCurrentBoot(String bootId) {
            SharedPreferences prefs = context.getSharedPreferences(
                    ROOT_ATTEMPT_PREFS, Context.MODE_PRIVATE);
            if (bootId.equals(prefs.getString(ROOT_ATTEMPT_BOOT_ID, "")))
                return "Root was already attempted during this boot";
            String sharedGate = "/data/local/tmp/.tcl_newselect_broker_attempt_"
                    + bootId;
            String legacyGate = "/data/local/tmp/.tcl_root_attempt_boot_" + bootId;
            String gate = runLocalAdbShell("if test -d " + quote(legacyGate)
                    + "; then echo ROOT_GATE_EXISTS; elif mkdir "
                    + quote(sharedGate)
                    + " 2>/dev/null; then mkdir " + quote(legacyGate)
                    + " 2>/dev/null || true; echo ROOT_GATE_OK; "
                    + "else echo ROOT_GATE_EXISTS; fi", 8);
            if (!gate.contains("ROOT_GATE_OK"))
                return "Root attempt gate is unavailable or already consumed\n" + gate;
            if (!prefs.edit().putString(ROOT_ATTEMPT_BOOT_ID, bootId).commit())
                return "Unable to persist the one-attempt-per-boot gate";
            return null;
        }

        private String runGhostLockViaLocalAdb(String bootId) {
            File nativeDir = new File(context.getApplicationInfo().nativeLibraryDir);
            File ghost = profile.ghost(nativeDir);
            File helper = new File(nativeDir, "libtclmcast.so");
            File handoff = profile.handoff(nativeDir);
            File preflight = profile.preflight(nativeDir);
            File ksud = new File(nativeDir, "libresukisuksud.so");
            File module = profile.module(nativeDir);

            String refusal = validateRootStartPreconditions();
            if (refusal != null) return "SECURITY REFUSAL:\n" + refusal;
            String preflightReport = runAdbPreflight();
            if (!preflightReport.contains("ADB SHELL COMPATIBLE 32/64"))
                return "PREFLIGHT REFUSED: GhostLock not started.\n"
                        + preflightReport;

            String statusPath = profile.statusPath(bootId);
            String exploitCommand = "echo $$ > " + quote(GHOST_PID_FILE)
                    + "; exec " + quote(ghost.getAbsolutePath()) + " --cred";
            int exploitTimeout = profile.experimental ? 240 : 180;
            String command = "cd /data/local/tmp && timeout "
                    + exploitTimeout + " env "
                    + profile.riskEnvironmentPrefix()
                    + "TCL_CAPTURE_FORCE_PERF=1 "
                    + "TCL_PERF_WITNESS=1 TCL_PERF_WITNESS_ATTEMPTS=5 "
                    + "TCL_PERF_RING_LOOPS=20000 "
                    + "TCL_W2_ATTEMPTS=1 TCL_REUSE_ATTEMPTS=1 "
                    + "TCL_MCAST_HELPER=" + quote(helper.getAbsolutePath()) + " "
                    + "TCL_RESUKISU_MANAGER_PACKAGE=" + quote(RESUKISU_PACKAGE) + " "
                    + "GHOST_RESUKISU_HANDOFF=" + quote(handoff.getAbsolutePath()) + " "
                    + "GHOST_RESUKISU_PREFLIGHT=" + quote(preflight.getAbsolutePath()) + " "
                    + "GHOST_RESUKISU_KSUD=" + quote(ksud.getAbsolutePath()) + " "
                    + "GHOST_RESUKISU_MODULE=" + quote(module.getAbsolutePath()) + " "
                    + "GHOST_RESUKISU_STATUS=" + quote(statusPath) + " "
                    + "GHOST_SELINUX=1 GHOST_SELINUX_PRESERVE_INIT=1 "
                    + "GHOST_EXEC=1 GHOST_REBOOT=0 GHOST_MINIMAL=1 "
                    + "GHOST_SID_SCAN=0 FOPS_MAX_ATTEMPTS=3 "
                    + "CRED_ATTEMPTS=1 KSNITCH_VERBOSE=0 "
                    + "/system/bin/sh -c " + quote(exploitCommand);
            String output = runLocalAdbShell(command, exploitTimeout + 20);
            if (output.length() > 14000)
                output = output.substring(output.length() - 14000);

            String verificationCommand =
                    "i=0; while [ $i -lt 75 ]; do "
                    + "if grep -q '^state=READY$' " + quote(statusPath)
                    + " 2>/dev/null || grep -q '^state=FAILED$' "
                    + quote(statusPath) + " 2>/dev/null; then break; fi; "
                    + "sleep 1; i=$((i+1)); done; "
                    + "echo HANDOFF_STATUS_BEGIN; cat " + quote(statusPath)
                    + " 2>/dev/null || echo state=UNAVAILABLE; "
                    + "echo HANDOFF_STATUS_END; "
                    + "caps=$(for cap in network_peer_controls open_perms "
                    + "extended_socket_class always_check_network cgroup_seclabel "
                    + "nnp_nosuid_transition genfs_seclabel_symlinks "
                    + "ioctl_skip_cloexec; do cat "
                    + "\"/sys/fs/selinux/policy_capabilities/$cap\" "
                    + "2>/dev/null || printf '?'; done | tr -d '\\r\\n'); "
                    + "echo POLICYCAPS=$caps; echo SELINUX=$(getenforce); "
                    + "echo AVB=$(getprop ro.boot.verifiedbootstate)/"
                    + "$(getprop ro.boot.vbmeta.device_state); "
                    + "echo MODULE=$(grep '^kernelsu ' /proc/modules "
                    + "2>/dev/null || echo hidden-or-absent); "
                    + quote(ksud.getAbsolutePath())
                    + " debug version 2>&1; echo KSUD_PROBE_RC=$?; "
                    + "echo ADB_LOCAL_POST=ok";
            String verification = runLocalAdbShell(verificationCommand, 100);
            boolean ready = verification.contains("state=READY")
                    && verification.contains("module=kernelsu")
                    && verification.contains("mode=volatile")
                    && verification.contains("late_load=ok")
                    && verification.contains("POLICYCAPS=11100100")
                    && verification.contains("SELINUX=Enforcing")
                    && verification.contains("AVB=green/locked")
                    && verification.contains("ADB_LOCAL_POST=ok")
                    && (verification.contains("Kernel Version:")
                            || verification.contains("MODULE=kernelsu "));
            return (ready ? "TCL_DIRECT_RESUKISU_READY\n"
                    : "TCL_DIRECT_RESUKISU_FAILED\n")
                    + "Automatic GhostLock W2 handoff:\n" + output
                    + "\n\nValidation:\n" + verification;
        }

        private String runAdbPreflight() {
            File nativeDir = new File(context.getApplicationInfo().nativeLibraryDir);
            File p32 = new File(nativeDir, "libtclpreflight.so");
            File p64 = new File(nativeDir, "libtclpreflight64.so");
            String output = runLocalAdbShell(
                    quote(p32.getAbsolutePath()) + "; r32=$?; "
                    + quote(p64.getAbsolutePath()) + "; r64=$?; "
                    + "echo PREFLIGHT_RC_32_64=$r32,$r64", 30);
            int first = output.indexOf("PREFLIGHT_OK");
            int second = first < 0 ? -1
                    : output.indexOf("PREFLIGHT_OK", first + 1);
            if (first >= 0 && second > first
                    && output.contains("PREFLIGHT_RC_32_64=0,0"))
                return "ADB SHELL COMPATIBLE 32/64\n" + output;
            return "ADB PREFLIGHT REFUSED\n" + output;
        }

        private AdbCrypto loadOrCreateLocalAdbCrypto() throws Exception {
            File privateKey = new File(context.getFilesDir(), "local-adb-key.pk8");
            File publicKey = new File(context.getFilesDir(),
                    "local-adb-key.pub.der");
            if (privateKey.isFile() && publicKey.isFile())
                return AdbCrypto.loadAdbKeyPair(
                        data -> Base64.encodeToString(data, Base64.NO_WRAP),
                        privateKey, publicKey);
            AdbCrypto crypto = AdbCrypto.generateAdbKeyPair(
                    data -> Base64.encodeToString(data, Base64.NO_WRAP));
            crypto.saveAdbKeyPair(privateKey, publicKey);
            return crypto;
        }

        private String runLocalAdbShell(String command, int timeoutSeconds) {
            Socket socket = null;
            AdbConnection connection = null;
            Thread watchdog = null;
            AtomicBoolean finished = new AtomicBoolean(false);
            AtomicBoolean expired = new AtomicBoolean(false);
            try {
                socket = connectLocalAdbWithRetry(timeoutSeconds);
                socket.setSoTimeout(Math.max(10, timeoutSeconds) * 1000);
                final Socket watched = socket;
                final long hardLimit = Math.max(10, timeoutSeconds) * 1000L;
                watchdog = new Thread(() -> {
                    try {
                        Thread.sleep(hardLimit);
                        if (!finished.get()) {
                            expired.set(true);
                            try {
                                watched.close();
                            } catch (Exception ignored) { }
                        }
                    } catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                    }
                }, "auto-root-adb-deadline");
                watchdog.setDaemon(true);
                watchdog.start();
                connection = AdbConnection.create(socket,
                        loadOrCreateLocalAdbCrypto());
                boolean connected = connection.connect(
                        Math.min(45, Math.max(10, timeoutSeconds)),
                        TimeUnit.SECONDS, false);
                if (!connected) return "ADB_LOCAL_NOT_AUTHORIZED";
                AdbStream stream = connection.open("shell:" + command);
                ByteArrayOutputStream output = new ByteArrayOutputStream();
                while (!stream.isClosed()) {
                    try {
                        byte[] chunk = stream.read();
                        if (chunk != null) output.write(chunk);
                    } catch (java.io.IOException closed) {
                        break;
                    }
                }
                stream.close();
                return new String(output.toByteArray(),
                        StandardCharsets.UTF_8).trim();
            } catch (Exception failure) {
                if (expired.get())
                    return "ADB_LOCAL_ABSOLUTE_TIMEOUT after "
                            + timeoutSeconds + " seconds";
                return "ADB_LOCAL_ERROR "
                        + failure.getClass().getSimpleName() + " : "
                        + failure.getMessage();
            } finally {
                finished.set(true);
                if (watchdog != null) watchdog.interrupt();
                try {
                    if (connection != null) connection.close();
                    else if (socket != null) socket.close();
                } catch (Exception ignored) { }
            }
        }

        private Socket connectLocalAdbWithRetry(int timeoutSeconds)
                throws Exception {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(
                    Math.min(20, Math.max(5, timeoutSeconds)));
            Exception last = null;
            int attempts = 0;
            do {
                Socket candidate = new Socket();
                attempts++;
                try {
                    candidate.connect(new InetSocketAddress("127.0.0.1", 5555),
                            1500);
                    return candidate;
                } catch (Exception failure) {
                    last = failure;
                    try {
                        candidate.close();
                    } catch (Exception ignored) { }
                    if (System.nanoTime() >= deadline) break;
                    SystemClock.sleep(500);
                }
            } while (System.nanoTime() < deadline);
            throw new java.net.ConnectException(
                    "127.0.0.1:5555 unavailable after " + attempts
                            + " attempts; last="
                            + (last == null ? "unknown" : last.getMessage()));
        }

        static String currentBootSessionId(Context context) {
            String bootId = readSmallFile(
                    new File("/proc/sys/kernel/random/boot_id"));
            if (validBootSessionId(bootId)) return bootId;
            try {
                int bootCount = Settings.Global.getInt(
                        context.getContentResolver(), Settings.Global.BOOT_COUNT, -1);
                if (bootCount >= 0) return "bootcount-" + bootCount;
            } catch (RuntimeException ignored) { }
            return "";
        }

        static boolean validBootSessionId(String value) {
            return value != null && (value.matches(
                    "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
                    || value.matches("bootcount-[0-9]{1,12}"));
        }

        private static String readSmallFile(File file) {
            try (FileInputStream in = new FileInputStream(file);
                    ByteArrayOutputStream out = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[128];
                int count;
                while ((count = in.read(buffer)) >= 0) {
                    if (count != 0) out.write(buffer, 0, count);
                    if (out.size() > 256) return "";
                }
                return new String(out.toByteArray(),
                        StandardCharsets.US_ASCII).trim();
            } catch (Exception ignored) {
                return "";
            }
        }

        private static String lineValue(String text, String key) {
            String prefix = key + "=";
            for (String line : text.split("\\r?\\n"))
                if (line.startsWith(prefix))
                    return line.substring(prefix.length()).trim();
            return "";
        }

        private static String quote(String value) {
            return "'" + value.replace("'", "'\\''") + "'";
        }

        private static String sha256(File file) {
            if (!file.isFile()) return "absent";
            try (InputStream in = new FileInputStream(file)) {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] buffer = new byte[32768];
                int count;
                while ((count = in.read(buffer)) >= 0)
                    if (count != 0) digest.update(buffer, 0, count);
                StringBuilder hex = new StringBuilder(64);
                for (byte value : digest.digest())
                    hex.append(String.format("%02x", value & 0xff));
                return hex.toString();
            } catch (Exception failure) {
                return "error-" + failure.getClass().getSimpleName();
            }
        }
    }
}
