package io.castellum.scan;

import java.util.List;

public enum ScanType {

    PING_SWEEP(List.of("-sn"), false, "30s"),
    SERVICE_DETECT(List.of("-sV"), true, "180s"),
    OS_FINGERPRINT(List.of("-O"), true, "180s");

    private final List<String> argv;
    private final boolean enumeratesPorts;
    private final String defaultHostTimeout;

    ScanType(List<String> argv, boolean enumeratesPorts, String defaultHostTimeout) {
        this.argv = List.copyOf(argv);
        this.enumeratesPorts = enumeratesPorts;
        this.defaultHostTimeout = defaultHostTimeout;
    }

    public List<String> argv() {
        return argv;
    }

    public boolean enumeratesPorts() {
        return enumeratesPorts;
    }

    public String defaultHostTimeout() {
        return defaultHostTimeout;
    }
}
