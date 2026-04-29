package io.castellum.scan;

import java.util.List;

public enum ScanType {

    PING_SWEEP(List.of("-sn")),
    SERVICE_DETECT(List.of("-sV")),
    OS_FINGERPRINT(List.of("-O"));

    private final List<String> argv;

    ScanType(List<String> argv) {
        this.argv = List.copyOf(argv);
    }

    public List<String> argv() {
        return argv;
    }
}
