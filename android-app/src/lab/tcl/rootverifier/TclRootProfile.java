package lab.tcl.rootverifier;

import java.io.File;

/**
 * Exact, build-pinned TCL root profiles shared by the foreground activity and
 * the opt-in boot worker.  A profile is selected only when firmware, kernel
 * and vendor SELinux policy all match; there is deliberately no generic V6xx
 * fallback.
 */
final class TclRootProfile {
    static final String POLICY_CAPS = "11100100";
    static final String ANDROID_RELEASE = "14";

    static final TclRootProfile V643 = new TclRootProfile(
            "v643", "V8-T653T01-LF1V643", "5.15.180-android14-11",
            "1930f6750090c816a3ea8cc32f752e2eec9b9e6d10d2851fe001fd690b069819",
            "1030054", false, "",
            "libtclghostlock.so",
            "6529ef8f76bd6dda073850f5fe227b808bd05e1a1a90e13cff24d06bb1d91b91",
            "libtclresukisuhandoff.so",
            "e519266c0a9774b63e48c8df7c813284073c320314121952bae18ecbfd5fd299",
            "libtclresukisupreflight.so",
            "8ce8a4dc9dec167ce5e04858e3cd83c1a7a0ec35573d55010aae88234d43a7c0",
            "libtclresukisumodule.so",
            "b6aeb907bd468852a11d7a90d121df87e1716f3b9549c69ee0190607e0d5f50c");

    static final TclRootProfile V637 = new TclRootProfile(
            "v637", "V8-T653T01-LF1V637", "5.15.180-android14-11",
            "1930f6750090c816a3ea8cc32f752e2eec9b9e6d10d2851fe001fd690b069819",
            "1030054", true, "TCL_V637_UNTESTED_ACK=I_ACCEPT_V637_KERNEL_PANIC_RISK",
            "libtclghostlockv637.so",
            "8560da058a4aa114f3dea5a12b1ee025ef63e0d5f9c5de10240a751eb20ddcdf",
            "libtclresukisuhandoffv637.so",
            "b2accc85827c9a053d4901b53c75028c51c67ef11f2ad5433d9ef57616d552a8",
            "libtclresukisupreflightv637.so",
            "8ce8a4dc9dec167ce5e04858e3cd83c1a7a0ec35573d55010aae88234d43a7c0",
            "libtclresukisumodulev637.so",
            "b6aeb907bd468852a11d7a90d121df87e1716f3b9549c69ee0190607e0d5f50c");

    static final TclRootProfile V655 = v65x(
            "v655", "V8-T653T01-LF1V655",
            "05910147a35a431e7fd12eb6e9d872a82002c6794cb929d4139c88df3d61b83d",
            "1044927");
    static final TclRootProfile V665 = v65x(
            "v665", "V8-T653T01-LF1V665",
            "8386bc2d38e3909c81eb9fc079d3acb7fa2f1271c77b02698091e35a7f61ed3c",
            "1045234");
    static final TclRootProfile V667 = v65x(
            "v667", "V8-T653T01-LF1V667",
            "8386bc2d38e3909c81eb9fc079d3acb7fa2f1271c77b02698091e35a7f61ed3c",
            "1045234");

    private static final TclRootProfile[] ALL = {
            V643, V637, V655, V665, V667
    };

    final String id;
    final String firmware;
    final String kernel;
    final String policySha256;
    final String policySize;
    final boolean experimental;
    final String riskEnvironment;
    final String ghostLibrary;
    final String ghostSha256;
    final String handoffLibrary;
    final String handoffSha256;
    final String preflightLibrary;
    final String preflightSha256;
    final String moduleLibrary;
    final String moduleSha256;

    private TclRootProfile(String id, String firmware, String kernel,
            String policySha256, String policySize, boolean experimental,
            String riskEnvironment, String ghostLibrary, String ghostSha256,
            String handoffLibrary, String handoffSha256,
            String preflightLibrary, String preflightSha256,
            String moduleLibrary, String moduleSha256) {
        this.id = id;
        this.firmware = firmware;
        this.kernel = kernel;
        this.policySha256 = policySha256;
        this.policySize = policySize;
        this.experimental = experimental;
        this.riskEnvironment = riskEnvironment;
        this.ghostLibrary = ghostLibrary;
        this.ghostSha256 = ghostSha256;
        this.handoffLibrary = handoffLibrary;
        this.handoffSha256 = handoffSha256;
        this.preflightLibrary = preflightLibrary;
        this.preflightSha256 = preflightSha256;
        this.moduleLibrary = moduleLibrary;
        this.moduleSha256 = moduleSha256;
    }

    private static TclRootProfile v65x(String id, String firmware,
            String policySha256, String policySize) {
        return new TclRootProfile(id, firmware, "5.15.192-android14-11",
                policySha256, policySize, true,
                "TCL_V65X_UNTESTED_ACK=I_ACCEPT_V65X_KERNEL_PANIC_RISK",
                "libtclghostlockv65x.so",
                "33be2fa096caa605f13d8f72345b9d550cf8c1ae0f97f15c81fba612d65d2aac",
                "libtclresukisuhandoffv65x.so",
                "3761bf8773c07425fe9fe85e78d4d2fc47a86c863e3b5ae67893bfe528c97027",
                "libtclresukisupreflightv65x.so",
                "25d74749b488f220db1fe49f660dbe1060ee6576c6f1d485eb8f86e2452f1a19",
                "libtclresukisumodulev65x.so",
                "48c64c0d8b85e62dd5db1125b32ea12cff91590d58138ad4a742ae19583b5db9");
    }

    String authorizationKey() {
        return firmware + "|" + kernel + "|android14";
    }

    String expectedState() {
        return firmware + "|" + kernel
                + "|14|1|green|locked|enforcing|Enforcing";
    }

    String statusPath(String bootId) {
        return "/data/local/tmp/.tcl_resukisu_" + id
                + "_handoff_" + bootId + ".status";
    }

    String riskEnvironmentPrefix() {
        return riskEnvironment.isEmpty() ? "" : riskEnvironment + " ";
    }

    File ghost(File nativeDir) {
        return new File(nativeDir, ghostLibrary);
    }

    File handoff(File nativeDir) {
        return new File(nativeDir, handoffLibrary);
    }

    File preflight(File nativeDir) {
        return new File(nativeDir, preflightLibrary);
    }

    File module(File nativeDir) {
        return new File(nativeDir, moduleLibrary);
    }

    static TclRootProfile exact(String state, String policySha256,
            String policySize) {
        for (TclRootProfile profile : ALL) {
            if (profile.expectedState().equals(state)
                    && profile.policySha256.equals(policySha256)
                    && profile.policySize.equals(policySize))
                return profile;
        }
        return null;
    }

    static TclRootProfile fromAuthorizationKey(String key) {
        for (TclRootProfile profile : ALL)
            if (profile.authorizationKey().equals(key)) return profile;
        return null;
    }

    static TclRootProfile fromFirmware(String firmware) {
        for (TclRootProfile profile : ALL)
            if (profile.firmware.equals(firmware)) return profile;
        return null;
    }

    static String supportedSummary() {
        return "V637, V643, V655, V665, V667";
    }
}
