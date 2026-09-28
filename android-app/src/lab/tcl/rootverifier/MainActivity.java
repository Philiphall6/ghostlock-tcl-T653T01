package lab.tcl.rootverifier;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.res.ColorStateList;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.os.Bundle;
import android.os.Process;
import android.provider.Settings;
import android.util.Base64;
import android.util.Log;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import com.tananaev.adblib.AdbConnection;
import com.tananaev.adblib.AdbCrypto;
import com.tananaev.adblib.AdbStream;

public final class MainActivity extends Activity {
    private static final String TAG = "TclRootVerifier";
    private static final String BROKER_NAME = "tcl_root_broker";
    private static final String RESPONSE_END = "@@END@@";
    private static final String RESUKISU_PACKAGE =
            "com.philiphall6.resukisu.tcl";
    private static final String RESUKISU_KMI = "android14-5.15";
    private static final String GHOSTLOCK_SHA256 =
            "6529ef8f76bd6dda073850f5fe227b808bd05e1a1a90e13cff24d06bb1d91b91";
    private static final String MCAST_HELPER_SHA256 =
            "4ca5692192b0a7598243f5070adf1e676ccd943aad4a292579ea69d38bbf1019";
    private static final String TCL_ROOT_BROKER_SHA256 =
            "cef1b8f896814ba2a8edc8f25e3b91b901e333f50b1c7add188a9ad940d04c86";
    private static final String TCL_RESUKISU_CLIENT_SHA256 =
            "81c66d09ca04078c31651475b5555b35f5a8c8f7ef7a5db935a59eb7470b83bb";
    private static final String TCL_RESUKISU_HANDOFF_SHA256 =
            "e519266c0a9774b63e48c8df7c813284073c320314121952bae18ecbfd5fd299";
    private static final String TCL_RESUKISU_PREFLIGHT_SHA256 =
            "8ce8a4dc9dec167ce5e04858e3cd83c1a7a0ec35573d55010aae88234d43a7c0";
    private static final String V643_POLICY_SHA256 =
            "1930f6750090c816a3ea8cc32f752e2eec9b9e6d10d2851fe001fd690b069819";
    private static final String V643_POLICY_SIZE = "1030054";
    private static final String RESUKISU_KSUD32_SHA256 =
            "528c80259613a1e27a90d8f202fda33ecceba9c1fd42e1d807fdbbc859af5e68";
    private static final String RESUKISU_KSUD64_SHA256 =
            "6cfa9081905445ba65cba3c01bfadc203c52665976d590f54dbd727be321cea0";
    private static final String RESUKISU_MODULE_SHA256 =
            "b6aeb907bd468852a11d7a90d121df87e1716f3b9549c69ee0190607e0d5f50c";
    private static final String RESUKISU_STAGED_MODULE =
            "/data/local/tmp/resukisu-tcl-v643.ko";
    private static final String RESUKISU_STAGED_KSUD =
            "/data/local/tmp/resukisu-ksud-armv7";
    private static final String GHOST_PID_FILE =
            "/data/local/tmp/.tcl_root_verifier_ghost.pid";
    private static final String ROOT_ATTEMPT_PREFS = "root_attempt_gate";
    private static final String ROOT_ATTEMPT_BOOT_ID = "consumed_boot_id";
    /* The direct-broker route is enabled only for the exact V643 profile.
     * It was validated twice on hardware, including vendor-policy/network
     * restoration and a parked UID-0 broker with no automatic reboot. */
    private static final boolean ROOT_ROUTE_VALIDATED = true;
    private static final String ROOT_ROUTE_HOLD_REASON =
            "ROOT REFUSED — hardware profile or V643 checks do not match.";
    private TextView result;
    private Button refresh;
    private Button adbKey;
    private Button preflight;
    private Button resukisuPreflight;
    private Button resukisuStage;
    private Button guidedRoot;
    private Button startRoot;
    private Button loadReSukiSu;
    private Button openReSukiSu;
    private Button stopRoot;
    private Button rebootStopReSukiSu;
    private Button autoRoot;
    private EditText explorerPath;
    private Button explorerParent;
    private Button explorerList;
    private Button explorerStat;
    private Button explorerRead;
    private static final Object brokerLock = new Object();
    private static LocalSocket brokerSocket;
    private static BufferedReader brokerReader;
    private static OutputStream brokerOutput;
    private static String brokerHello = "";
    private static volatile boolean brokerWaiting;
    private static volatile boolean rootStarting;
    private static volatile boolean guidedRunning;
    private static volatile boolean resukisuActive;
    private boolean firstResume = true;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);

        ScrollView page = new ScrollView(this);
        page.setFillViewport(true);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(48, 32, 48, 32);
        root.setBackgroundColor(Color.rgb(16, 20, 24));

        TextView title = new TextView(this);
        title.setText(R.string.app_title);
        title.setTextColor(Color.WHITE);
        title.setTextSize(28);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        root.addView(title);

        refresh = new Button(this);
        refresh.setText(R.string.action_verify);
        refresh.setTextSize(18);
        refresh.setGravity(Gravity.CENTER);
        styleButton(refresh);
        refresh.setOnClickListener(v -> runChecks());
        root.addView(refresh);

        adbKey = new Button(this);
        adbKey.setText(R.string.action_local_adb);
        adbKey.setTextSize(18);
        adbKey.setGravity(Gravity.CENTER);
        styleButton(adbKey);
        adbKey.setOnClickListener(v -> authorizeLocalAdb());
        root.addView(adbKey);

        startRoot = new Button(this);
        startRoot.setText(R.string.action_root);
        startRoot.setTextSize(18);
        startRoot.setGravity(Gravity.CENTER);
        styleButton(startRoot);
        startRoot.setOnClickListener(v -> startRootChain());
        root.addView(startRoot);

        openReSukiSu = new Button(this);
        openReSukiSu.setText(R.string.action_open_manager);
        openReSukiSu.setTextSize(18);
        openReSukiSu.setGravity(Gravity.CENTER);
        styleButton(openReSukiSu);
        openReSukiSu.setOnClickListener(v -> openReSukiSuManager());
        root.addView(openReSukiSu);

        rebootStopReSukiSu = new Button(this);
        rebootStopReSukiSu.setText(R.string.action_stop_root);
        rebootStopReSukiSu.setTextSize(18);
        rebootStopReSukiSu.setGravity(Gravity.CENTER);
        styleButton(rebootStopReSukiSu);
        rebootStopReSukiSu.setOnClickListener(v -> confirmRebootStopReSukiSu());
        root.addView(rebootStopReSukiSu);

        autoRoot = new Button(this);
        autoRoot.setTextSize(18);
        autoRoot.setGravity(Gravity.CENTER);
        styleButton(autoRoot);
        autoRoot.setOnClickListener(v -> toggleAutoRoot());
        root.addView(autoRoot);
        updateAutoRootButton(false);

        TextView notice = new TextView(this);
        notice.setText(R.string.chain_notice);
        notice.setTextColor(Color.rgb(190, 220, 255));
        notice.setTextSize(16);
        root.addView(notice);

        result = new TextView(this);
        result.setTextColor(Color.rgb(225, 235, 240));
        result.setTextSize(19);
        result.setTypeface(Typeface.MONOSPACE);
        result.setTextIsSelectable(true);
        result.setMinHeight(480);

        root.addView(result, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT));

        page.addView(root, new ScrollView.LayoutParams(
                ScrollView.LayoutParams.MATCH_PARENT,
                ScrollView.LayoutParams.WRAP_CONTENT));
        setContentView(page);
        runChecks();
        if (getIntent().getBooleanExtra("autoconnect", false))
            waitForBroker();
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (firstResume) {
            firstResume = false;
        } else if (result != null && refresh != null && refresh.isEnabled()) {
            /* Returning from ReSukiSU Manager is the usual point at which this
             * app has just received its own su grant.  Re-check and unlock the
             * auto-root control only after that grant is actually observable. */
            runChecks();
        }
    }

    private Button explorerButton(String label, View.OnClickListener action) {
        Button button = new Button(this);
        button.setText(label);
        button.setTextSize(15);
        button.setGravity(Gravity.CENTER);
        styleButton(button);
        button.setOnClickListener(action);
        return button;
    }

    private static void styleButton(Button button) {
        int focused = Color.rgb(24, 119, 242);
        int pressed = Color.rgb(13, 71, 161);
        int normal = Color.rgb(92, 92, 96);
        int disabled = Color.rgb(42, 45, 48);
        button.setBackgroundTintList(new ColorStateList(
                new int[][] {
                        new int[] {android.R.attr.state_pressed},
                        new int[] {android.R.attr.state_focused},
                        new int[] {-android.R.attr.state_enabled},
                        new int[] {}
                },
                new int[] {pressed, focused, disabled, normal}));
        button.setTextColor(new ColorStateList(
                new int[][] {
                        new int[] {-android.R.attr.state_enabled},
                        new int[] {}
                },
                new int[] {Color.rgb(110, 115, 120), Color.WHITE}));
    }

    private static LinearLayout.LayoutParams weightedButtonParams() {
        return new LinearLayout.LayoutParams(0,
                LinearLayout.LayoutParams.WRAP_CONTENT, 1);
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        if (intent.getBooleanExtra("autoconnect", false))
            waitForBroker();
    }

    private void authorizeLocalAdb() {
        adbKey.setEnabled(false);
        result.setText(R.string.adb_key_generating);
        new Thread(() -> {
            String report = testLocalAdb();
            boolean localAdbReady = report.contains("ADB_LOCAL_OK");
            boolean active = brokerConnected();
            boolean attemptConsumed = !localAdbReady
                    || rootAttemptConsumedThisBoot();
            runOnUiThread(() -> {
                result.setText(report);
                adbKey.setEnabled(true);
                startRoot.setEnabled(ROOT_ROUTE_VALIDATED && !active
                        && !rootStarting && !attemptConsumed);
                adbKey.requestFocus();
            });
        }, "local-adb-auth").start();
    }

    private void updateAutoRootButton(boolean appRootValidated) {
        if (autoRoot == null) return;
        boolean enabled = AutoRootState.isEnabled(this);
        if (enabled) {
            autoRoot.setText(R.string.action_auto_root_on);
            /* Keeping an armed option selectable even without root is an
             * intentional safety escape hatch: it can always be turned off. */
            autoRoot.setEnabled(true);
        } else if (appRootValidated) {
            autoRoot.setText(R.string.action_auto_root_off);
            autoRoot.setEnabled(true);
        } else {
            autoRoot.setText(R.string.action_auto_root_requires_root);
            autoRoot.setEnabled(false);
        }
    }

    private void toggleAutoRoot() {
        if (AutoRootState.isEnabled(this)) {
            AutoRootState.disable(this, "Disabled manually from the TV app");
            audit("AUTO_ROOT_DISABLED_BY_USER");
            updateAutoRootButton(false);
            result.setText(R.string.auto_root_disabled);
            autoRoot.requestFocus();
            return;
        }

        autoRoot.setEnabled(false);
        result.setText(R.string.auto_root_checking);
        new Thread(() -> {
            String proof = validateAutoRootEligibility();
            boolean allowed = proof.startsWith("AUTO_ROOT_ELIGIBLE\n");
            runOnUiThread(() -> {
                if (!allowed) {
                    result.setText(getString(R.string.auto_root_refused)
                            + "\n\n" + proof);
                    updateAutoRootButton(false);
                    return;
                }
                new AlertDialog.Builder(this)
                        .setTitle(R.string.auto_root_confirm_title)
                        .setMessage(R.string.auto_root_confirm_message)
                        .setNegativeButton(R.string.cancel, (dialog, which) -> {
                            updateAutoRootButton(true);
                            autoRoot.requestFocus();
                        })
                        .setPositiveButton(R.string.enable, (dialog, which) -> {
                            boolean stored = AutoRootState
                                    .enableForValidatedV643(this);
                            audit("AUTO_ROOT_ENABLE stored=" + stored);
                            updateAutoRootButton(stored);
                            result.setText(stored
                                    ? R.string.auto_root_enabled
                                    : R.string.auto_root_store_failed);
                            autoRoot.requestFocus();
                        })
                        .show();
            });
        }, "auto-root-eligibility").start();
    }

    private String validateAutoRootEligibility() {
        File ksud = new File(getApplicationInfo().nativeLibraryDir,
                "libresukisuksud.so");
        String driver = commandWithTimeout(new String[]{
                ksud.getAbsolutePath(), "debug", "version"}, 5);
        String rootProbe = commandWithTimeout(new String[]{
                "/system/bin/sh", "-c",
                "su -c 'printf \"ROOT_ID=\"; id; "
                        + "printf \"STATE=%s|%s|%s|%s|%s|%s|%s\\n\" "
                        + "\"$(getprop ro.software.version_id)\" "
                        + "\"$(uname -r)\" "
                        + "\"$(getprop ro.build.version.release)\" "
                        + "\"$(getprop ro.boot.verifiedbootstate)\" "
                        + "\"$(getprop ro.boot.vbmeta.device_state)\" "
                        + "\"$(getprop ro.boot.veritymode)\" "
                        + "\"$(getenforce)\"; "
                        + "printf \"POLICY_SHA=\"; sha256sum "
                        + "/vendor/etc/selinux/precompiled_sepolicy "
                        + "| cut -d\" \" -f1; "
                        + "printf \"POLICY_SIZE=\"; wc -c < "
                        + "/vendor/etc/selinux/precompiled_sepolicy "
                        + "| tr -d \" \"; "
                        + "printf \"MODULE=\"; grep -Ec \"^kernelsu \" "
                        + "/proc/modules 2>/dev/null || true'"}, 12);
        String adb = runLocalAdbShell("echo ADB_LOCAL_OK", 15);
        String expected = "STATE=V8-T653T01-LF1V643|"
                + "5.15.180-android14-11|14|green|locked|enforcing|Enforcing";
        boolean root = rootProbe.contains("ROOT_ID=uid=0");
        boolean exactProfile = rootProbe.contains(expected)
                && rootProbe.contains("POLICY_SHA=" + V643_POLICY_SHA256)
                && rootProbe.contains("POLICY_SIZE=" + V643_POLICY_SIZE)
                && rootProbe.contains("MODULE=1");
        boolean driverActive = driver.contains("Kernel Version:");
        boolean adbReady = adb.contains("ADB_LOCAL_OK");
        if (root && exactProfile && driverActive && adbReady)
            return "AUTO_ROOT_ELIGIBLE\n" + rootProbe
                    + "\nDRIVER=" + driver + "\n" + adb;
        return "AUTO_ROOT_NOT_ELIGIBLE"
                + "\napp_su_uid0=" + root
                + "\nexact_v643_profile=" + exactProfile
                + "\nvolatile_driver=" + driverActive
                + "\nlocal_adb=" + adbReady
                + "\n\n" + rootProbe
                + "\n\n" + driver + "\n\n" + adb;
    }

    private boolean appHasValidatedRoot() {
        File ksud = new File(getApplicationInfo().nativeLibraryDir,
                "libresukisuksud.so");
        String su = commandWithTimeout(new String[]{
                "/system/bin/sh", "-c", "su -c /system/bin/id"}, 4);
        String driver = commandWithTimeout(new String[]{
                ksud.getAbsolutePath(), "debug", "version"}, 4);
        return su.contains("uid=0") && driver.contains("Kernel Version:");
    }

    private String testLocalAdb() {
        String shell = runLocalAdbShell(
                "id; id -Z 2>/dev/null; getenforce; echo ADB_LOCAL_OK", 45);
        if (shell.startsWith("ADB_LOCAL_NOT_AUTHORIZED"))
            return "LOCAL ADB: WAITING FOR AUTHORIZATION\n"
                    + "Approve the key on screen, then press the button again.\n"
                    + "Root was not started.";
        if (shell.startsWith("ADB_LOCAL_ERROR"))
            return "LOCAL ADB FAILED\n" + shell + "\nRoot was not started.";
        if (!shell.contains("ADB_LOCAL_OK"))
            return "LOCAL ADB CONNECTED, but the shell test is incomplete:\n" + shell;
        return "LOCAL ADB AUTHORIZED — NON-ROOT TEST\n\n" + shell
                + "\n\nCommand executed by the ADB shell domain."
                + "\nGhostLock was not started.";
    }

    private AdbCrypto loadOrCreateLocalAdbCrypto() throws Exception {
        File privateKey = new File(getFilesDir(), "local-adb-key.pk8");
        File publicKey = new File(getFilesDir(), "local-adb-key.pub.der");
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
            final Socket watchedSocket = socket;
            final long hardLimitMs = Math.max(10, timeoutSeconds) * 1000L;
            watchdog = new Thread(() -> {
                try {
                    Thread.sleep(hardLimitMs);
                    if (!finished.get()) {
                        expired.set(true);
                        try {
                            watchedSocket.close();
                        } catch (Exception ignored) { }
                    }
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
            }, "local-adb-hard-deadline");
            watchdog.setDaemon(true);
            watchdog.start();
            connection = AdbConnection.create(socket, loadOrCreateLocalAdbCrypto());
            boolean connected = connection.connect(
                    Math.min(45, Math.max(10, timeoutSeconds)),
                    TimeUnit.SECONDS, false);
            if (!connected)
                return "ADB_LOCAL_NOT_AUTHORIZED";

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
            return new String(output.toByteArray(), StandardCharsets.UTF_8).trim();
        } catch (Exception e) {
            if (expired.get())
                return "ADB_LOCAL_ABSOLUTE_TIMEOUT after " + timeoutSeconds
                        + " seconds";
            return "ADB_LOCAL_ERROR " + e.getClass().getSimpleName()
                    + " : " + e.getMessage();
        } finally {
            finished.set(true);
            if (watchdog != null) watchdog.interrupt();
            try {
                if (connection != null) connection.close();
                else if (socket != null) socket.close();
            } catch (Exception ignored) { }
        }
    }

    /*
     * adbd can briefly close its TCP listener while the one-shot root handoff
     * completes.  A single connect() made that harmless transition look like
     * a root failure even when the module had already reached READY.  Retry is
     * deliberately bounded and read-only: this never starts/restarts adbd and
     * never changes a property on the TV.
     */
    private Socket connectLocalAdbWithRetry(int timeoutSeconds) throws Exception {
        final long retryNanos = TimeUnit.SECONDS.toNanos(
                Math.min(20, Math.max(5, timeoutSeconds)));
        final long deadline = System.nanoTime() + retryNanos;
        Exception lastFailure = null;
        int attempts = 0;
        do {
            Socket candidate = new Socket();
            attempts++;
            try {
                candidate.connect(new InetSocketAddress("127.0.0.1", 5555),
                        1500);
                if (attempts > 1)
                    Log.i(TAG, "ADB_LOCAL_RECONNECTED attempts=" + attempts);
                return candidate;
            } catch (Exception failure) {
                lastFailure = failure;
                try {
                    candidate.close();
                } catch (Exception ignored) { }
                if (System.nanoTime() >= deadline) break;
                try {
                    Thread.sleep(500);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw interrupted;
                }
            }
        } while (System.nanoTime() < deadline);
        throw new java.net.ConnectException(
                "127.0.0.1:5555 unavailable after " + attempts
                + " attempts; last error="
                + (lastFailure == null ? "unknown" : lastFailure.getMessage()));
    }

    private void waitForBroker() {
        if (brokerWaiting || brokerSocket != null) return;
        brokerWaiting = true;
        new Thread(() -> {
            try {
                for (int i = 0; i < 360; i++) {
                    String state = brokerId();
                    if (state.contains("uid=0") && state.contains("selinux=1")) {
                        Log.i(TAG, "BROKER_SESSION_READY " + state);
                        audit("SESSION_READY " + state.replace('\n', ' '));
                        if (!guidedRunning) runOnUiThread(this::runChecks);
                        return;
                    }
                    try {
                        Thread.sleep(250);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }
                Log.e(TAG, "BROKER_SESSION_TIMEOUT");
            } finally {
                brokerWaiting = false;
            }
        }, "broker-autoconnect").start();
    }

    private void startBrokerConnectorForRoot() {
        if (brokerWaiting || brokerSocket != null) return;
        brokerWaiting = true;
        new Thread(() -> {
            try {
                for (int i = 0; i < 360 && rootStarting; i++) {
                    String state = brokerId();
                    if (state.contains("uid=0") && state.contains("euid=0")
                            && state.contains("selinux=1")) {
                        Log.i(TAG, "DIRECT_BROKER_READY " + state);
                        audit("DIRECT_BROKER_READY " + state.replace('\n', ' '));
                        return;
                    }
                    try {
                        Thread.sleep(250);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }
                Log.e(TAG, "DIRECT_BROKER_CONNECTOR_STOPPED");
            } finally {
                brokerWaiting = false;
            }
        }, "direct-broker-connector").start();
    }

    private void startRootChain() {
        if (rootStarting) return;
        if (!ROOT_ROUTE_VALIDATED) {
            result.setText(ROOT_ROUTE_HOLD_REASON);
            audit("ROOT_START_REFUSED route_validation_hold");
            return;
        }
        rootStarting = true;
        startRoot.setEnabled(false);
        result.setText(R.string.root_starting);
        audit("ROOT_START_REQUEST uid=" + Process.myUid());
        new Thread(() -> {
            String outcome;
            boolean active = false;
            boolean attempted = false;
            String refusal = validateRootStartPreconditions();
            if (refusal != null) {
                outcome = "ROOT REFUSED BEFORE EXPLOIT\n\n" + refusal;
                audit("ROOT_START_REFUSED " + oneLineTail(refusal, 1000));
            } else {
                String resukisu = buildReSukiSuPreflightReport();
                boolean bundleReady = resukisu.contains(
                                "ARMv7 manager       : PRESENT")
                        && resukisu.contains("ARMv7 ksud         : VALID")
                        && resukisu.contains("AArch64/GKI ksud   : VALID")
                        && resukisu.contains("Exact TCL module   : VALID")
                        && resukisu.contains("Expected TCL kernel: YES")
                        && resukisu.contains("Build T653T01 V643 : YES");
                if (!bundleReady) {
                    outcome = "ROOT REFUSED — RESUKISU BUNDLE DOES NOT MATCH\n\n"
                            + resukisu;
                    audit("ROOT_START_REFUSED resukisu_bundle");
                } else {
                    String gateFailure = consumeRootAttemptForCurrentBoot();
                    if (gateFailure != null) {
                        outcome = gateFailure;
                        audit("ROOT_START_REFUSED "
                                + gateFailure.replace('\n', ' '));
                    } else {
                        attempted = true;
                        synchronized (brokerLock) {
                            closeBrokerLocked();
                        }
                        outcome = runGhostLockViaLocalAdb();
                        active = outcome.contains(
                                "TCL_DIRECT_RESUKISU_READY");
                        resukisuActive = active;
                        if (!active)
                            outcome += "\n\nRESUKISU NOT LOADED: "
                                    + "direct handoff was not validated.";
                    }
                }
            }
            Log.i(TAG, "ROOT_CHAIN_RESULT " + outcome.replace('\n', ' '));
            audit("ROOT_CHAIN_RESULT " + oneLineTail(outcome, 800));
            final String finalOutcome = outcome;
            final boolean finalActive = active;
            final boolean finalAttempted = attempted;
            final boolean finalAppRoot = finalActive && appHasValidatedRoot();
            rootStarting = false;
            runOnUiThread(() -> {
                startRoot.setEnabled(!finalActive && !finalAttempted);
                updateAutoRootButton(finalAppRoot);
                result.setText(finalOutcome);
            });
        }, "adb-ghostlock").start();
    }

    private void stopRootSession() {
        stopRoot.setEnabled(false);
        result.setText("Safely stopping the root session…\n"
                + "Network policy will be restored before SELinux, "
                + "without an automatic reboot.");
        new Thread(() -> {
            String reply = brokerCommand("STOP");
            synchronized (brokerLock) {
                closeBrokerLocked();
            }
            audit("SESSION_STOP " + reply.replace('\n', ' '));
            runOnUiThread(() -> result.setText(
                    "ROOT SESSION STOPPED — NO REBOOT\n\n"
                    + "Policy capabilities/netlink are restored before enforcing. "
                    + "The W2 holder and broker remain parked to retain their "
                    + "references until a possible manual reboot."));
        }, "broker-stop").start();
    }

    private void runGuidedRootSequence() {
        if (guidedRunning || rootStarting) return;
        if (!ROOT_ROUTE_VALIDATED) {
            result.setText(ROOT_ROUTE_HOLD_REASON);
            audit("GUIDED_ROOT_REFUSED route_validation_hold");
            return;
        }
        guidedRunning = true;
        guidedRoot.setEnabled(false);
        result.setText("ALL-IN-ONE — step 1/6: checking local ADB…");
        new Thread(() -> {
            boolean active = false;
            String failure = null;
            try {
                String adb = testLocalAdb();
                if (!adb.contains("LOCAL ADB AUTHORIZED")) {
                    failure = "STEP 1/6 REFUSED — authorize the local ADB key first.\n\n"
                            + adb;
                    return;
                }

                guidedStatus("ALL-IN-ONE — step 2/6: checking 32/64-bit compatibility…");
                String compatibility = runAdbPreflight();
                if (!compatibility.contains("ADB SHELL COMPATIBLE 32/64")) {
                    failure = "STEP 2/6 REFUSED\n\n" + compatibility;
                    return;
                }

                guidedStatus("ALL-IN-ONE — step 3/6: checking ReSukiSU/V643…");
                String resukisu = buildReSukiSuPreflightReport();
                boolean resukisuReady = resukisu.contains("ARMv7 manager       : PRESENT")
                        && resukisu.contains("ARMv7 ksud         : VALID")
                        && resukisu.contains("Expected TCL kernel: YES")
                        && resukisu.contains("Build T653T01 V643 : YES")
                        && resukisu.contains("Exact TCL module   : VALID");
                if (!resukisuReady) {
                    failure = "STEP 3/6 REFUSED\n\n" + resukisu;
                    return;
                }

                guidedStatus("ALL-IN-ONE — step 4/6: embedded signed handoff…");

                String already = runLocalAdbShell(
                        "grep '^kernelsu ' /proc/modules 2>/dev/null || true", 15);
                if (already.contains("kernelsu ")) {
                    active = true;
                    audit("GUIDED_SEQUENCE module_already_active");
                    return;
                }

                String gateFailure = consumeRootAttemptForCurrentBoot();
                if (gateFailure != null) {
                    failure = "STEP 5/6 REFUSED\n\n" + gateFailure;
                    return;
                }

                guidedStatus("ALL-IN-ONE — step 5/6: one-shot W2 to ReSukiSU…");
                rootStarting = true;
                String ghost = runGhostLockViaLocalAdb();
                rootStarting = false;
                active = ghost.contains("TCL_DIRECT_RESUKISU_READY");
                resukisuActive = active;
                if (!active) {
                    failure = "STEP 5/6 REFUSED — ReSukiSU handoff not validated\n\n"
                            + oneLineTail(ghost, 8000)
                            + "\n\nDo not retry before a full reboot.";
                    return;
                }
                guidedStatus("ALL-IN-ONE — step 6/6: ReSukiSU active, SELinux enforcing");
            } finally {
                rootStarting = false;
                guidedRunning = false;
                final boolean finalActive = active;
                final String finalFailure = failure;
                final boolean finalAppRoot = finalActive && appHasValidatedRoot();
                runOnUiThread(() -> {
                    guidedRoot.setEnabled(ROOT_ROUTE_VALIDATED);
                    startRoot.setEnabled(ROOT_ROUTE_VALIDATED && !finalActive);
                    loadReSukiSu.setEnabled(false);
                    stopRoot.setEnabled(false);
                    setExplorerEnabled(false);
                    updateAutoRootButton(finalAppRoot);
                    if (finalFailure != null) {
                        result.setText("ALL-IN-ONE STOPPED WITHOUT CONTINUING\n\n"
                                + finalFailure);
                    } else if (finalActive) {
                        result.setText("ALL-IN-ONE COMPLETE\n\n"
                                + "RESUKISU TCL V643 ACTIVE — TEMPORARY MODULE\n"
                                + "You can now open ReSukiSU Manager.\n"
                                + "Rebooting the TV will remove the module.");
                    }
                });
                audit("GUIDED_SEQUENCE active=" + active
                        + " failure=" + (failure != null));
                Log.i(TAG, "GUIDED_RESULT active=" + active + " failure="
                        + (failure == null ? "none" : oneLineTail(failure, 1500)));
            }
        }, "guided-root-sequence").start();
    }

    private void guidedStatus(String text) {
        Log.i(TAG, "GUIDED_STATUS " + text.replace('\n', ' '));
        runOnUiThread(() -> result.setText(text));
    }

    private void openReSukiSuManager() {
        /* An intermediate dialog sometimes captured D-pad focus on Google TV.
         * This button has no privileged effect, so it can directly open the
         * installed manager. */
        launchReSukiSuManager();
    }

    private void launchReSukiSuManager() {
        Intent launch = getPackageManager().getLeanbackLaunchIntentForPackage(
                RESUKISU_PACKAGE);
        if (launch == null)
            launch = getPackageManager().getLaunchIntentForPackage(RESUKISU_PACKAGE);
        if (launch == null) {
            result.setText(R.string.manager_missing);
            return;
        }
        launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(launch);
    }

    private void confirmRebootStopReSukiSu() {
        new AlertDialog.Builder(this)
                .setTitle(R.string.stop_root_title)
                .setMessage(R.string.stop_root_message)
                .setNegativeButton(R.string.cancel, null)
                .setPositiveButton(R.string.reboot, (dialog, which) -> {
                    result.setText(R.string.stopping_root);
                    audit("ROOT_STOP_REBOOT_REQUEST");
                    new Thread(() -> {
                        String reply = brokerConnected()
                                ? brokerCommand("STOP") : "broker already absent";
                        synchronized (brokerLock) {
                            closeBrokerLocked();
                        }
                        try {
                            Thread.sleep(1000);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        }
                        String reboot = runLocalAdbShell("sync; reboot", 15);
                        audit("ROOT_STOP reply=" + oneLineTail(reply, 300)
                                + " reboot=" + oneLineTail(reboot, 300));
                        resukisuActive = false;
                    }, "root-stop-reboot").start();
                })
                .show();
    }

    private void confirmReSukiSuLoad() {
        if (!brokerConnected()) {
            result.setText("LOAD REFUSED: start temporary root first.");
            return;
        }
        new AlertDialog.Builder(this)
                .setTitle("Load the temporary kernel module?")
                .setMessage("Restricted to TCL T653T01 V643 / 5.15.180-android14-11. "
                        + "Preflight rejects any mismatch. Loading does not flash "
                        + "anything and disappears at reboot, but a kernel module "
                        + "can cause an abrupt reboot.")
                .setNegativeButton("CANCEL", null)
                .setPositiveButton("LOAD", (dialog, which) -> loadReSukiSuModule())
                .show();
    }

    private void loadReSukiSuModule() {
        loadReSukiSu.setEnabled(false);
        result.setText("Deploying the module and loader autonomously…");
        new Thread(() -> {
            ReSukiSuLoadOutcome outcome = performReSukiSuLoad(false);
            runOnUiThread(() -> {
                result.setText(outcome.report);
                loadReSukiSu.setEnabled(brokerConnected() && !outcome.active);
            });
        }, "resukisu-load").start();
    }

    private static final class ReSukiSuLoadOutcome {
        final boolean active;
        final String report;

        ReSukiSuLoadOutcome(boolean active, String report) {
            this.active = active;
            this.report = report;
        }
    }

    private ReSukiSuLoadOutcome performReSukiSuLoad(boolean alreadyStaged) {
        if (!alreadyStaged) {
            String staging = stageReSukiSuViaLocalAdb();
            if (!staging.contains("STAGING_OK")) {
                audit("RESUKISU_STAGING_REFUSED "
                        + oneLineTail(staging, 1200));
                return new ReSukiSuLoadOutcome(false,
                        "AUTONOMOUS DEPLOYMENT REFUSED — no module loaded\n\n"
                                + staging);
            }
        }

        File helper = new File(getApplicationInfo().nativeLibraryDir,
                "libtclresukisupreflight.so");
        String preflightCommand =
                "echo CONTEXT=$(id -Z 2>/dev/null); "
                + "echo ENFORCING=$(getenforce); "
                + "echo KERNEL=$(uname -r); "
                + "echo FW=$(getprop ro.software.version_id); "
                + "echo AVB=$(getprop ro.boot.verifiedbootstate)/$(getprop ro.boot.vbmeta.device_state); "
                + "echo MODULE_SHA=$(sha256sum " + RESUKISU_STAGED_MODULE + " 2>/dev/null | cut -d' ' -f1); "
                + "echo KSUD_SHA=$(sha256sum " + RESUKISU_STAGED_KSUD + " 2>/dev/null | cut -d' ' -f1); "
                + shellQuote(helper.getAbsolutePath()) + "; echo HELPER_RC=$?";
        String preflightResult = brokerCommand("EXEC " + preflightCommand);
        boolean approved = preflightResult.contains("PREFLIGHT_OK")
                && preflightResult.contains("HELPER_RC=0")
                && preflightResult.contains("ENFORCING=Enforcing")
                && preflightResult.contains("KERNEL=5.15.180-android14-11")
                && preflightResult.contains("FW=V8-T653T01-LF1V643")
                && preflightResult.contains("AVB=green/locked")
                && preflightResult.contains("MODULE_SHA=" + RESUKISU_MODULE_SHA256)
                && preflightResult.contains("KSUD_SHA=" + RESUKISU_KSUD32_SHA256);
        if (!approved) {
            audit("RESUKISU_LOAD_REFUSED " + oneLineTail(preflightResult, 1200));
            return new ReSukiSuLoadOutcome(false,
                    "LOAD REFUSED — no module loaded\n\n" + preflightResult);
        }

        String loadCommand = shellQuote(RESUKISU_STAGED_KSUD)
                + " insmod " + shellQuote(RESUKISU_STAGED_MODULE)
                + " allow_shell=1 2>&1; rc=$?; echo LOAD_RC=$rc; "
                + "grep '^kernelsu ' /proc/modules 2>/dev/null || true";
        String loadResult = brokerCommand("EXEC " + loadCommand);
        boolean active = loadResult.contains("LOAD_RC=0")
                && loadResult.contains("kernelsu ");
        audit("RESUKISU_LOAD active=" + active + " "
                + oneLineTail(loadResult, 1200));
        if (active)
            return new ReSukiSuLoadOutcome(true,
                    "RESUKISU TCL V643 ACTIVE — TEMPORARY MODULE\n\n"
                            + loadResult
                            + "\n\nNo flashing was performed. The module disappears at reboot.");
        return new ReSukiSuLoadOutcome(false,
                "FAILURE/UNKNOWN STATE — do not retry before analysis\n\n"
                        + loadResult);
    }

    private String stageReSukiSuViaLocalAdb() {
        File nativeDir = new File(getApplicationInfo().nativeLibraryDir);
        File embeddedModule = new File(nativeDir, "libtclresukisumodule.so");
        File embeddedKsud = new File(nativeDir, "libresukisuksud.so");
        String moduleHash = sha256(embeddedModule);
        String ksudHash = sha256(embeddedKsud);
        if (!RESUKISU_MODULE_SHA256.equals(moduleHash)
                || !RESUKISU_KSUD32_SHA256.equals(ksudHash)) {
            return "STAGING_FAIL embedded_hash\nmodule=" + moduleHash
                    + "\nksud=" + ksudHash;
        }

        String moduleTemp = RESUKISU_STAGED_MODULE + ".new";
        String ksudTemp = RESUKISU_STAGED_KSUD + ".new";
        String command = "set -e; "
                + "rm -f " + shellQuote(moduleTemp) + " " + shellQuote(ksudTemp) + "; "
                + "cp " + shellQuote(embeddedModule.getAbsolutePath()) + " "
                + shellQuote(moduleTemp) + "; "
                + "cp " + shellQuote(embeddedKsud.getAbsolutePath()) + " "
                + shellQuote(ksudTemp) + "; "
                + "chmod 600 " + shellQuote(moduleTemp) + "; "
                + "chmod 700 " + shellQuote(ksudTemp) + "; "
                + "module_hash=$(sha256sum " + shellQuote(moduleTemp)
                + " | cut -d' ' -f1); "
                + "ksud_hash=$(sha256sum " + shellQuote(ksudTemp)
                + " | cut -d' ' -f1); "
                + "test \"$module_hash\" = " + shellQuote(RESUKISU_MODULE_SHA256) + "; "
                + "test \"$ksud_hash\" = " + shellQuote(RESUKISU_KSUD32_SHA256) + "; "
                + "mv -f " + shellQuote(moduleTemp) + " "
                + shellQuote(RESUKISU_STAGED_MODULE) + "; "
                + "mv -f " + shellQuote(ksudTemp) + " "
                + shellQuote(RESUKISU_STAGED_KSUD) + "; "
                + "echo MODULE_SHA=$module_hash; echo KSUD_SHA=$ksud_hash; "
                + "ls -lZ " + shellQuote(RESUKISU_STAGED_MODULE) + " "
                + shellQuote(RESUKISU_STAGED_KSUD) + "; echo STAGING_OK";
        String output = runLocalAdbShell(command, 45);
        if (!output.contains("STAGING_OK")
                || !output.contains("MODULE_SHA=" + RESUKISU_MODULE_SHA256)
                || !output.contains("KSUD_SHA=" + RESUKISU_KSUD32_SHA256))
            return "STAGING_FAIL adb_copy\n" + output;
        audit("RESUKISU_STAGING_OK module=" + RESUKISU_MODULE_SHA256
                + " ksud=" + RESUKISU_KSUD32_SHA256);
        return output;
    }

    private void setExplorerEnabled(boolean enabled) {
        if (explorerParent != null) explorerParent.setEnabled(enabled);
        if (explorerList != null) explorerList.setEnabled(enabled);
        if (explorerStat != null) explorerStat.setEnabled(enabled);
        if (explorerRead != null) explorerRead.setEnabled(enabled);
        if (explorerPath != null) explorerPath.setEnabled(enabled);
    }

    private void explorerParent() {
        String path = explorerPath.getText().toString().trim();
        if (path.isEmpty() || "/".equals(path)) {
            explorerPath.setText("/");
        } else {
            File parent = new File(path).getParentFile();
            explorerPath.setText(parent == null ? "/" : parent.getPath());
        }
        explorerCommand("FS_LIST");
    }

    private void explorerCommand(String operation) {
        String path = explorerPath.getText().toString().trim();
        if (!path.startsWith("/")) {
            result.setText("EXPLORER REFUSED: use an absolute path.");
            return;
        }
        if (!brokerConnected()) {
            result.setText("EXPLORER UNAVAILABLE: no active root session.");
            return;
        }
        setExplorerEnabled(false);
        result.setText("Read-only root explorer…\n" + path);
        new Thread(() -> {
            String encoded = hexEncode(path.getBytes(StandardCharsets.UTF_8));
            String response = brokerCommand(operation + " " + encoded);
            String formatted = formatExplorerResponse(response);
            audit("FS_READ_ONLY " + operation + " " + path);
            runOnUiThread(() -> {
                result.setText(formatted);
                setExplorerEnabled(brokerConnected());
                explorerPath.requestFocus();
            });
        }, "root-readonly-explorer").start();
    }

    private static String hexEncode(byte[] data) {
        final char[] digits = "0123456789abcdef".toCharArray();
        char[] out = new char[data.length * 2];
        for (int i = 0; i < data.length; i++) {
            int value = data[i] & 0xff;
            out[i * 2] = digits[value >>> 4];
            out[i * 2 + 1] = digits[value & 15];
        }
        return new String(out);
    }

    private static byte[] hexDecode(String text) {
        if ((text.length() & 1) != 0) return new byte[0];
        byte[] out = new byte[text.length() / 2];
        for (int i = 0; i < text.length(); i += 2) {
            int high = Character.digit(text.charAt(i), 16);
            int low = Character.digit(text.charAt(i + 1), 16);
            if (high < 0 || low < 0) return new byte[0];
            out[i / 2] = (byte)((high << 4) | low);
        }
        return out;
    }

    private static String safePreview(byte[] data) {
        String decoded = new String(data, StandardCharsets.UTF_8);
        StringBuilder safe = new StringBuilder(decoded.length());
        for (int i = 0; i < decoded.length(); i++) {
            char c = decoded.charAt(i);
            if (c == '\n' || c == '\r' || c == '\t' ||
                    (!Character.isISOControl(c) && c != '\ufffd'))
                safe.append(c);
            else
                safe.append('·');
        }
        return safe.toString();
    }

    private static String formatExplorerResponse(String response) {
        int firstBreak = response.indexOf('\n');
        if (response.startsWith("SESSION ") && firstBreak >= 0)
            response = response.substring(firstBreak + 1);
        String[] lines = response.split("\\n");
        StringBuilder out = new StringBuilder();
        out.append("ROOT — READ ONLY — SELINUX ENFORCING\n");
        for (String line : lines) {
            String[] fields = line.split("\\t", -1);
            if (fields.length >= 7 && "ENTRY".equals(fields[0])) {
                String name = new String(hexDecode(fields[6]), StandardCharsets.UTF_8);
                out.append(fields[1]).append(' ')
                        .append(fields[2]).append(' ')
                        .append(fields[3]).append(':').append(fields[4]).append(' ')
                        .append(fields[5]).append(' ')
                        .append(name);
                if ("d".equals(fields[1])) out.append('/');
                out.append('\n');
            } else if (fields.length >= 2 && "DATA".equals(fields[0])) {
                out.append("\n--- PREVIEW (32 KiB maximum) ---\n")
                        .append(safePreview(hexDecode(fields[1]))).append('\n');
            } else if (line.startsWith("FS_LIST\t")) {
                out.append("Directory: ").append(line.substring(8)).append('\n');
            } else if (line.startsWith("FS_FILE\t")) {
                out.append("File: ").append(line.substring(8)).append('\n');
            } else if (line.startsWith("FS_STAT\t")) {
                out.append("Information: ").append(line.substring(8)).append('\n');
            } else if (line.startsWith("FS_END\t")) {
                out.append("\nSummary: ").append(line.substring(7)).append('\n');
            } else if (line.startsWith("FS_ERROR")) {
                out.append("REFUSED/ERROR: ").append(line).append('\n');
            }
        }
        out.append("\nDRM areas, keys, user data, persist, block devices, and SELinux are blocked.");
        return out.toString();
    }

    private void runPreflightOnly() {
        preflight.setEnabled(false);
        result.setText("Running preflight through ADB shell — no exploit started…");
        new Thread(() -> {
            String report = runAdbPreflight();
            runOnUiThread(() -> {
                result.setText(report);
                preflight.setEnabled(true);
                preflight.requestFocus();
            });
        }, "adb-preflight").start();
    }

    private String runAdbPreflight() {
        File nativeDir = new File(getApplicationInfo().nativeLibraryDir);
        File p32 = new File(nativeDir, "libtclpreflight.so");
        File p64 = new File(nativeDir, "libtclpreflight64.so");
        String command = p32.getAbsolutePath() + "; r32=$?; "
                + p64.getAbsolutePath() + "; r64=$?; "
                + "echo PREFLIGHT_RC_32_64=$r32,$r64";
        String output = runLocalAdbShell(command, 30);
        int first = output.indexOf("PREFLIGHT_OK");
        int second = first < 0 ? -1 : output.indexOf("PREFLIGHT_OK", first + 1);
        if (first >= 0 && second > first && output.contains("PREFLIGHT_RC_32_64=0,0"))
            return "ADB SHELL COMPATIBLE 32/64 — WITHOUT ROOT\n" + output;
        return "ADB PREFLIGHT REFUSED — GhostLock not started\n" + output;
    }

    private String runNativePreflight() {
        try {
            StringBuilder combined = new StringBuilder();
            String[] binaries = {"libtclpreflight.so", "libtclpreflight64.so"};
            for (String name : binaries) {
                File binary = new File(getApplicationInfo().nativeLibraryDir, name);
                if (!binary.canExecute())
                    return "UNTRUSTED_APP BLOCKED\n"
                            + name + " is absent or not executable.\n"
                            + "GhostLock was not started.";
                ProcessBuilder builder = new ProcessBuilder(binary.getAbsolutePath());
                builder.redirectErrorStream(true);
                java.lang.Process child = builder.start();
                if (!child.waitFor(10, TimeUnit.SECONDS)) {
                    child.destroyForcibly();
                    return "UNTRUSTED_APP BLOCKED\n"
                            + name + ": timeout exceeded.\n"
                            + "GhostLock was not started.";
                }
                int rc = child.exitValue();
                String output = readStream(child.getInputStream()).trim();
                child.destroy();
                combined.append(name).append(":\n")
                        .append(output).append("\nrc=").append(rc).append('\n');
                if (rc != 0 || !output.contains("PREFLIGHT_OK"))
                    return "UNTRUSTED_APP BLOCKED — GhostLock not started\n"
                            + combined;
            }
            return "UNTRUSTED_APP COMPATIBLE 32/64\n" + combined;
        } catch (Exception e) {
            return "UNTRUSTED_APP BLOCKED\nGhostLock was not started.\n"
                    + e.getClass().getSimpleName() + " : " + e.getMessage();
        }
    }

    private void runReSukiSuPreflight() {
        resukisuPreflight.setEnabled(false);
        result.setText("Checking ReSukiSU ARMv7/AArch64 — no module loaded…");
        new Thread(() -> {
            String report = buildReSukiSuPreflightReport();
            runOnUiThread(() -> {
                result.setText(report);
                resukisuPreflight.setEnabled(true);
                resukisuPreflight.requestFocus();
            });
        }, "resukisu-preflight").start();
    }

    private void runReSukiSuStaging() {
        resukisuStage.setEnabled(false);
        result.setText("Deploying ReSukiSU autonomously into /data/local/tmp…");
        new Thread(() -> {
            String report = stageReSukiSuViaLocalAdb();
            runOnUiThread(() -> {
                if (report.contains("STAGING_OK"))
                    result.setText("RESUKISU FILES READY — MODULE NOT LOADED\n\n"
                            + report);
                else
                    result.setText("DEPLOYMENT FAILED — MODULE NOT LOADED\n\n"
                            + report);
                resukisuStage.setEnabled(true);
                resukisuStage.requestFocus();
            });
        }, "resukisu-staging").start();
    }

    private String buildReSukiSuPreflightReport() {
        File nativeDir = new File(getApplicationInfo().nativeLibraryDir);
        File ksud32 = new File(nativeDir, "libresukisuksud.so");
        File ksud64 = new File(nativeDir, "libresukisuksud64.so");
        File exactModule = new File(nativeDir, "libtclresukisumodule.so");
        String hash32 = sha256(ksud32);
        String hash64 = sha256(ksud64);
        String moduleHash = sha256(exactModule);
        boolean trusted32 = RESUKISU_KSUD32_SHA256.equals(hash32);
        boolean trusted64 = RESUKISU_KSUD64_SHA256.equals(hash64);
        boolean trustedModule = RESUKISU_MODULE_SHA256.equals(moduleHash);

        String manager = "ABSENT";
        try {
            PackageInfo info = getPackageManager().getPackageInfo(
                    RESUKISU_PACKAGE, PackageManager.GET_META_DATA);
            manager = "PRESENT" + (info.versionName == null
                    ? "" : " — version " + info.versionName);
        } catch (PackageManager.NameNotFoundException ignored) { }

        String command = "echo KERNEL=$(uname -r); "
                + "echo ABI=$(getprop ro.product.cpu.abilist); "
                + "echo DISPLAY=$(getprop ro.build.display.id); "
                + "echo SOFTWARE=$(getprop ro.software.version_id); "
                + "echo MODULE=$(grep '^kernelsu ' /proc/modules 2>/dev/null || echo absent); "
                + "echo KSUD32_BEGIN; " + shellQuote(ksud32.getAbsolutePath())
                + " --version 2>&1; echo KSUD32_RC=$?";
        String adb = runLocalAdbShell(command, 30);
        boolean tclKernel = adb.contains("KERNEL=5.15.180-android14-11");
        boolean tclBuild = adb.contains("T653T01") && adb.contains("V643");
        boolean unloaded = adb.contains("MODULE=absent");

        StringBuilder out = new StringBuilder();
        out.append("RESUKISU — PRE-INTEGRATION WITHOUT LOADING\n\n");
        out.append("ARMv7 manager       : ").append(manager).append('\n');
        out.append("ARMv7 ksud         : ").append(trusted32 ? "VALID" : "REFUSED")
                .append("\n  SHA-256 ").append(hash32).append('\n');
        out.append("AArch64/GKI ksud   : ").append(trusted64 ? "VALID" : "REFUSED")
                .append("\n  SHA-256 ").append(hash64).append('\n');
        out.append("Exact TCL module   : ").append(trustedModule ? "VALID" : "REFUSED")
                .append("\n  SHA-256 ").append(moduleHash).append('\n');
        out.append("Expected TCL kernel: ").append(tclKernel ? "YES" : "NO").append('\n');
        out.append("Build T653T01 V643 : ").append(tclBuild ? "YES" : "NO").append('\n');
        out.append("Generic KMI        : NOT REQUIRED — exact TCL module\n");
        out.append("KernelSU module    : ").append(unloaded ? "NOT LOADED" : "ALREADY PRESENT/UNKNOWN")
                .append("\n\n").append(adb).append('\n');
        out.append("\nNO MODULE WAS LOADED.\n");
        out.append("Activation remains separate and subject to root/KMI/SELinux checks.");
        audit("RESUKISU_PREFLIGHT trusted32=" + trusted32
                + " trusted64=" + trusted64 + " exactModule=" + trustedModule);
        return out.toString();
    }

    private static String shellQuote(String value) {
        return "'" + value.replace("'", "'\\''") + "'";
    }

    private static String sha256(File file) {
        if (!file.isFile()) return "absent";
        try (InputStream in = new FileInputStream(file)) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[32768];
            int count;
            while ((count = in.read(buffer)) >= 0) {
                if (count != 0) digest.update(buffer, 0, count);
            }
            return hexEncode(digest.digest());
        } catch (Exception e) {
            return "error-" + e.getClass().getSimpleName();
        }
    }

    private String validateRootStartPreconditions() {
        String adb = testLocalAdb();
        if (!adb.contains("LOCAL ADB AUTHORIZED"))
            return "Local ADB is unauthorized or unavailable.\n" + adb;

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

        String expectedState = "V8-T653T01-LF1V643|"
                + "5.15.180-android14-11|14|1|green|locked|enforcing|Enforcing";
        String state = lineValue(probe, "STATE");
        String uptimeText = lineValue(probe, "UPTIME");
        String policyHash = lineValue(probe, "POLICY_SHA");
        String policySize = lineValue(probe, "POLICY_SIZE");
        String policyCaps = lineValue(probe, "POLICYCAPS");
        String modules = lineValue(probe, "MODULES");

        long uptime;
        try {
            uptime = Long.parseLong(uptimeText);
        } catch (Exception e) {
            return "Unable to read uptime; exploit was not started.\n"
                    + probe;
        }
        if (!expectedState.equals(state))
            return "Security profile differs from the validated V643 profile.\n"
                    + probe;
        if (uptime > 900)
            return "Boot is not fresh (uptime=" + uptime
                    + " s). Reboot the TV before one single attempt.";
        if (!V643_POLICY_SHA256.equals(policyHash)
                || !V643_POLICY_SIZE.equals(policySize))
            return "Vendor SELinux policy does not match; safe restoration is "
                    + "impossible.\n" + probe;
        if (!"11100100".equals(policyCaps))
            return "SELinux policy capabilities are already altered; exploit was not started.\n"
                    + probe;
        if (!"0".equals(modules))
            return "A root module is already loaded; no new attempt is allowed.\n"
                    + probe;
        return null;
    }

    private static String lineValue(String text, String key) {
        String prefix = key + "=";
        for (String line : text.split("\\r?\\n")) {
            if (line.startsWith(prefix))
                return line.substring(prefix.length()).trim();
        }
        return "";
    }

    private String runGhostLockViaLocalAdb() {
        if (!ROOT_ROUTE_VALIDATED)
            return ROOT_ROUTE_HOLD_REASON + "\nGhostLock was not executed.";
        try {
            File nativeDir = new File(getApplicationInfo().nativeLibraryDir);
            File ghost = new File(nativeDir, "libtclghostlock.so");
            File helper = new File(nativeDir, "libtclmcast.so");
            File handoff = new File(nativeDir, "libtclresukisuhandoff.so");
            File resukisuPreflight = new File(nativeDir,
                    "libtclresukisupreflight.so");
            File ksud = new File(nativeDir, "libresukisuksud.so");
            File module = new File(nativeDir, "libtclresukisumodule.so");
            if (!ghost.canExecute() || !helper.canExecute()
                    || !handoff.canExecute() || !resukisuPreflight.canExecute()
                    || !ksud.canExecute() || !module.canRead())
                return "FAILURE: native binaries are missing or not executable.";
            if (!GHOSTLOCK_SHA256.equals(sha256(ghost)) ||
                    !MCAST_HELPER_SHA256.equals(sha256(helper)) ||
                    !TCL_RESUKISU_HANDOFF_SHA256.equals(sha256(handoff)) ||
                    !TCL_RESUKISU_PREFLIGHT_SHA256.equals(
                            sha256(resukisuPreflight)) ||
                    !RESUKISU_KSUD32_SHA256.equals(sha256(ksud)) ||
                    !RESUKISU_MODULE_SHA256.equals(sha256(module)))
                return "INTEGRITY REFUSAL: GhostLock, helper, or handoff does "
                        + "not match the pinned V643 hashes.";

            String refusal = validateRootStartPreconditions();
            if (refusal != null)
                return "SECURITY REFUSAL:\n" + refusal;

            String preflightReport = runAdbPreflight();
            if (!preflightReport.contains("ADB SHELL COMPATIBLE 32/64"))
                return "PREFLIGHT REFUSED: GhostLock not started.\n"
                        + preflightReport;

            String bootSession = currentBootSessionId();
            if (!validBootSessionId(bootSession))
                return "SECURITY REFUSAL: boot identifier is unavailable.";
            String statusPath = "/data/local/tmp/.tcl_resukisu_handoff_"
                    + bootSession + ".status";
            String exploitCommand = "echo $$ > "
                    + shellQuote(GHOST_PID_FILE) + "; exec "
                    + shellQuote(ghost.getAbsolutePath()) + " --cred";
            String command = "cd /data/local/tmp && timeout 180 env "
                    + "TCL_CAPTURE_FORCE_PERF=1 "
                    + "TCL_PERF_WITNESS=1 TCL_PERF_WITNESS_ATTEMPTS=5 "
                    + "TCL_PERF_RING_LOOPS=20000 "
                    + "TCL_W2_ATTEMPTS=1 TCL_REUSE_ATTEMPTS=1 "
                    + "TCL_MCAST_HELPER="
                    + shellQuote(helper.getAbsolutePath()) + " "
                    + "TCL_RESUKISU_MANAGER_PACKAGE="
                    + shellQuote(RESUKISU_PACKAGE) + " "
                    + "GHOST_RESUKISU_HANDOFF="
                    + shellQuote(handoff.getAbsolutePath()) + " "
                    + "GHOST_RESUKISU_PREFLIGHT="
                    + shellQuote(resukisuPreflight.getAbsolutePath()) + " "
                    + "GHOST_RESUKISU_KSUD="
                    + shellQuote(ksud.getAbsolutePath()) + " "
                    + "GHOST_RESUKISU_MODULE="
                    + shellQuote(module.getAbsolutePath()) + " "
                    + "GHOST_RESUKISU_STATUS="
                    + shellQuote(statusPath) + " "
                    + "GHOST_SELINUX=1 GHOST_SELINUX_PRESERVE_INIT=1 "
                    + "GHOST_EXEC=1 GHOST_REBOOT=0 GHOST_MINIMAL=1 "
                    + "GHOST_SID_SCAN=0 FOPS_MAX_ATTEMPTS=3 "
                    + "CRED_ATTEMPTS=1 KSNITCH_VERBOSE=0 "
                    + "/system/bin/sh -c " + shellQuote(exploitCommand);
            String output = runLocalAdbShell(command, 200);
            if (output.length() > 14000)
                output = output.substring(output.length() - 14000);

            String verificationCommand =
                    "i=0; while [ $i -lt 75 ]; do "
                    + "if grep -q '^state=READY$' " + shellQuote(statusPath)
                    + " 2>/dev/null || grep -q '^state=FAILED$' "
                    + shellQuote(statusPath) + " 2>/dev/null; then break; fi; "
                    + "sleep 1; i=$((i+1)); done; "
                    + "echo HANDOFF_STATUS_BEGIN; cat "
                    + shellQuote(statusPath)
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
                    + shellQuote(ksud.getAbsolutePath())
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
            return (ready ? "TCL_DIRECT_RESUKISU_READY\n" :
                    "TCL_DIRECT_RESUKISU_FAILED\n")
                    + "GhostLock W2 → direct UID-0 handoff:\n" + output
                    + "\n\nHandoff/ReSukiSU validation:\n" + verification;
        } catch (Exception e) {
            return "LAUNCH FAILURE: " + e.getClass().getSimpleName()
                    + " : " + e.getMessage();
        }
    }

    private String cleanupGhostLockViaLocalAdb() {
        String command = "pid=$(cat " + shellQuote(GHOST_PID_FILE)
                + " 2>/dev/null || true); "
                + "case \"$pid\" in ''|*[!0-9]*) exit 0;; esac; "
                + "cmd=$(tr '\\000' ' ' < /proc/$pid/cmdline 2>/dev/null || true); "
                + "case \"$cmd\" in *libtclghostlock.so*--cred*) "
                + "kill -TERM $pid 2>/dev/null || true; sleep 1; "
                + "kill -KILL $pid 2>/dev/null || true;; esac; "
                + "rm -f " + shellQuote(GHOST_PID_FILE) + "; echo CLEANUP_DONE";
        String output = runLocalAdbShell(command, 15);
        audit("GHOST_CLEANUP " + oneLineTail(output, 500));
        return output;
    }

    private void runChecks() {
        refresh.setEnabled(false);
        result.setText("Verification in progress…");
        new Thread(() -> {
            final String report = buildReport();
            final boolean appRootValidated = report.contains(
                            "ROOT AVAILABLE THROUGH SU: YES")
                    && report.contains("VOLATILE ROOT DRIVER ACTIVE: YES");
            runOnUiThread(() -> {
                result.setText(report);
                refresh.setEnabled(true);
                boolean active = brokerConnected();
                boolean attemptConsumed = rootAttemptConsumedThisBoot();
                startRoot.setEnabled(ROOT_ROUTE_VALIDATED && !active
                        && !rootStarting && !attemptConsumed);
                updateAutoRootButton(appRootValidated);
                refresh.requestFocus();
            });
        }, "root-verifier").start();
    }

    private String currentBootId() {
        File bootId = new File("/proc/sys/kernel/random/boot_id");
        try (FileInputStream in = new FileInputStream(bootId);
                ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[128];
            int count;
            while ((count = in.read(buffer)) >= 0) {
                if (count != 0) out.write(buffer, 0, count);
                if (out.size() > 256) return "";
            }
            return new String(out.toByteArray(), StandardCharsets.US_ASCII).trim();
        } catch (Exception e) {
            Log.e(TAG, "BOOT_ID_UNAVAILABLE", e);
            return "";
        }
    }

    private String currentBootSessionId() {
        String bootId = currentBootId();
        if (validBootId(bootId)) return bootId;
        try {
            int bootCount = Settings.Global.getInt(getContentResolver(),
                    Settings.Global.BOOT_COUNT, -1);
            if (bootCount >= 0) return "bootcount-" + bootCount;
        } catch (Exception e) {
            Log.e(TAG, "BOOT_COUNT_UNAVAILABLE", e);
        }
        return "";
    }

    private boolean rootAttemptConsumedThisBoot() {
        String bootId = currentBootSessionId();
        if (!validBootSessionId(bootId)) return true;
        String consumed = getSharedPreferences(ROOT_ATTEMPT_PREFS, MODE_PRIVATE)
                .getString(ROOT_ATTEMPT_BOOT_ID, "");
        if (bootId.equals(consumed)) return true;
        String sharedGate = "/data/local/tmp/.tcl_newselect_broker_attempt_"
                + bootId;
        String legacyGate = "/data/local/tmp/.tcl_root_attempt_boot_" + bootId;
        String state = runLocalAdbShell("if test -d "
                + shellQuote(sharedGate) + " || test -d "
                + shellQuote(legacyGate)
                + "; then echo ROOT_GATE_EXISTS; else echo ROOT_GATE_CLEAR; fi", 8);
        return !state.contains("ROOT_GATE_CLEAR");
    }

    private static boolean validBootId(String bootId) {
        return bootId != null && bootId.matches(
                "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
    }

    private static boolean validBootSessionId(String sessionId) {
        return validBootId(sessionId) || (sessionId != null
                && sessionId.matches("bootcount-[0-9]{1,12}"));
    }

    /*
     * GhostLock changes live kernel state even when a later carrier misses.
     * Never begin a second W2 chain on the same boot: only a reboot provides a
     * known-clean kernel session.  The marker is written before the exploit.
     */
    private String consumeRootAttemptForCurrentBoot() {
        String bootId = currentBootSessionId();
        if (!validBootSessionId(bootId))
            return "ROOT REFUSED — boot identifier is inaccessible.\n"
                    + "No attempt was started.";
        android.content.SharedPreferences prefs =
                getSharedPreferences(ROOT_ATTEMPT_PREFS, MODE_PRIVATE);
        if (bootId.equals(prefs.getString(ROOT_ATTEMPT_BOOT_ID, "")))
            return "ROOT WAS ALREADY ATTEMPTED DURING THIS BOOT.\n"
                    + "Fully reboot the TV before another attempt.";
        String sharedGate = "/data/local/tmp/.tcl_newselect_broker_attempt_"
                + bootId;
        String legacyGate = "/data/local/tmp/.tcl_root_attempt_boot_" + bootId;
        String gateResult = runLocalAdbShell("if test -d "
                + shellQuote(legacyGate) + "; then echo ROOT_GATE_EXISTS; "
                + "elif mkdir " + shellQuote(sharedGate)
                + " 2>/dev/null; then mkdir " + shellQuote(legacyGate)
                + " 2>/dev/null || true; echo ROOT_GATE_OK; "
                + "else echo ROOT_GATE_EXISTS; fi", 8);
        if (!gateResult.contains("ROOT_GATE_OK"))
            return "ROOT ALREADY ATTEMPTED OR BOOT GUARD UNAVAILABLE.\n"
                    + "Fully reboot the TV before another attempt.\n"
                    + oneLineTail(gateResult, 500);
        if (!prefs.edit().putString(ROOT_ATTEMPT_BOOT_ID, bootId).commit())
            return "ROOT REFUSED — unable to record the session guard.\n"
                    + "No attempt was started.";
        audit("ROOT_ATTEMPT_CONSUMED boot_id=" + bootId);
        return null;
    }

    private String buildReport() {
        StringBuilder out = new StringBuilder();
        out.append("Application UID : ").append(Process.myUid()).append('\n');
        out.append("App context     : ").append(command("/system/bin/id")).append('\n');
        out.append("SELinux         : ").append(command("/system/bin/getenforce")).append('\n');
        out.append("Raw SELinux     : ").append(readFile("/sys/fs/selinux/enforce")).append('\n');
        out.append("Verified Boot   : ").append(command("/system/bin/getprop", "ro.boot.verifiedbootstate")).append('\n');
        out.append("VBMeta          : ").append(command("/system/bin/getprop", "ro.boot.vbmeta.device_state")).append('\n');
        out.append("Verity          : ").append(command("/system/bin/getprop", "ro.boot.veritymode")).append('\n');
        out.append("Build           : ").append(command("/system/bin/getprop", "ro.build.display.id")).append('\n');

        String[] paths = {
                "/system/bin/su", "/system/xbin/su", "/sbin/su",
                "/data/local/bin/su", "/data/adb/magisk", "/debug_ramdisk/.magisk"
        };
        boolean pathFound = false;
        out.append("\nsu/Magisk indicators:\n");
        for (String path : paths) {
            boolean present = new File(path).exists();
            pathFound |= present;
            out.append(present ? "  [PRESENT] " : "  [absent]  ").append(path).append('\n');
        }

        String su = commandWithTimeout(
                new String[]{"/system/bin/sh", "-c", "su -c /system/bin/id"}, 4);
        File ksud = new File(getApplicationInfo().nativeLibraryDir,
                "libresukisuksud.so");
        String driver = commandWithTimeout(new String[]{
                ksud.getAbsolutePath(), "debug", "version"}, 4);
        boolean suRoot = su.contains("uid=0");
        boolean driverActive = driver.contains("Kernel Version:");
        out.append("\nReal `su -c id` test: ").append(su).append('\n');
        out.append("ReSukiSU driver       : ").append(driver).append('\n');
        out.append("\n========================================\n");
        if (suRoot) {
            out.append("ROOT AVAILABLE THROUGH SU: YES\n");
        } else {
            out.append("ROOT AVAILABLE THROUGH SU: NO\n");
        }
        out.append("VOLATILE ROOT DRIVER ACTIVE: ")
                .append(driverActive ? "YES" : "NO").append('\n');
        if (!suRoot && !driverActive)
            out.append("No root process is currently reachable.\n");
        out.append("su/Magisk indicator  : ").append(pathFound ? "PRESENT" : "ABSENT").append('\n');
        out.append("GhostLock starts only after an explicit local-ADB action.\n");
        out.append("_newselect/PI route gate: ")
                .append(ROOT_ROUTE_VALIDATED ? "VALIDATED" : "BLOCKED").append('\n');
        if (!ROOT_ROUTE_VALIDATED)
            out.append("Reason: offline validation is complete, but the new route "
                    + "is not yet validated on TCL hardware; TV launch is disabled.\n");
        out.append("Integrated mode: GhostLock UID-0 child → direct handoff → "
                + "ReSukiSU v1.0 exact.\n");
        out.append("adbd remains UID 2000; global root is provided by su/ReSukiSU.\n");
        out.append("The STOP button closes the session and then reboots the TV.\n");
        out.append("Automatic root at boot: ")
                .append(AutoRootState.isEnabled(this) ? "ON" : "OFF")
                .append('\n');
        out.append("Auto-root last status: ")
                .append(AutoRootState.lastStatus(this)).append('\n');
        String audit = readFile(new File(getFilesDir(), "root-session-audit.log").getAbsolutePath());
        if (!audit.startsWith("inaccessible")) {
            if (audit.length() > 3000) audit = audit.substring(audit.length() - 3000);
            out.append("\nSession log:\n").append(audit).append('\n');
        }
        return out.toString();
    }

    private static boolean brokerConnected() {
        synchronized (brokerLock) {
            return brokerSocket != null;
        }
    }

    private void audit(String event) {
        File log = new File(getFilesDir(), "root-session-audit.log");
        String line = System.currentTimeMillis() + " " + event + "\n";
        try (FileOutputStream out = new FileOutputStream(log, true)) {
            out.write(line.getBytes(StandardCharsets.UTF_8));
            out.flush();
        } catch (Exception e) {
            Log.e(TAG, "audit write failed", e);
        }
    }

    private static String oneLineTail(String value, int limit) {
        String line = value.replace('\n', ' ').replace('\r', ' ');
        return line.length() <= limit ? line : line.substring(line.length() - limit);
    }

    private String brokerId() {
        return brokerCommand("ID");
    }

    private String brokerCommand(String command) {
        synchronized (brokerLock) {
            try {
                if (brokerSocket == null) {
                    LocalSocket socket = new LocalSocket();
                    socket.setSoTimeout(15000);
                    socket.connect(new LocalSocketAddress(
                            BROKER_NAME, LocalSocketAddress.Namespace.ABSTRACT));
                    BufferedReader reader = new BufferedReader(
                            new InputStreamReader(socket.getInputStream(),
                                    StandardCharsets.UTF_8));
                    String hello = reader.readLine();
                    if (hello == null || !hello.startsWith("SESSION ")) {
                        socket.close();
                        throw new IllegalStateException("broker handshake: " + hello);
                    }
                    brokerSocket = socket;
                    brokerReader = reader;
                    brokerOutput = socket.getOutputStream();
                    brokerHello = hello;
                }

                brokerOutput.write((command + "\n").getBytes(StandardCharsets.UTF_8));
                brokerOutput.flush();
                StringBuilder response = new StringBuilder();
                for (;;) {
                    String line = brokerReader.readLine();
                    if (line == null) throw new IllegalStateException("broker disconnected");
                    if (RESPONSE_END.equals(line)) break;
                    if (response.length() != 0) response.append('\n');
                    response.append(line);
                }
                String text = response.toString().trim();
                return brokerHello + (text.isEmpty() ? "" : "\n" + text);
            } catch (Exception e) {
                closeBrokerLocked();
                return "unavailable (" + e.getClass().getSimpleName() + ")";
            }
        }
    }

    private void closeBrokerLocked() {
        try {
            if (brokerSocket != null) brokerSocket.close();
        } catch (Exception ignored) { }
        brokerSocket = null;
        brokerReader = null;
        brokerOutput = null;
        brokerHello = "";
    }

    @Override
    protected void onDestroy() {
        /* The process intentionally retains the socket. STOP closes the app
         * session; the holder and broker remain parked until a possible
         * manual reboot. */
        super.onDestroy();
    }

    private static String command(String... argv) {
        return commandWithTimeout(argv, 3);
    }

    private static String commandWithTimeout(String[] argv, int seconds) {
        ProcessBuilder builder = new ProcessBuilder(argv);
        builder.redirectErrorStream(true);
        java.lang.Process child = null;
        try {
            child = builder.start();
            if (!child.waitFor(seconds, TimeUnit.SECONDS)) {
                child.destroyForcibly();
                return "TIMEOUT";
            }
            String text = readStream(child.getInputStream()).trim();
            return text.isEmpty() ? "(no output, rc=" + child.exitValue() + ")" : text;
        } catch (Exception e) {
            return "unavailable (" + e.getClass().getSimpleName() + ")";
        } finally {
            if (child != null) child.destroy();
        }
    }

    private static String readFile(String path) {
        try (InputStream in = new FileInputStream(path)) {
            String value = readStream(in).trim();
            return "1".equals(value) ? "1 (enforcing)" :
                    "0".equals(value) ? "0 (permissif)" : value;
        } catch (Exception e) {
            return "inaccessible (" + e.getClass().getSimpleName() + ")";
        }
    }

    private static String readStream(InputStream in) throws Exception {
        BufferedReader reader = new BufferedReader(
                new InputStreamReader(in, StandardCharsets.UTF_8));
        StringBuilder text = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            if (text.length() != 0) text.append('\n');
            text.append(line);
        }
        return text.toString();
    }
}
