package io.castellum.scan;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Positive;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

@Component
@ConfigurationProperties(prefix = "castellum.scan.nmap")
@Validated
public class NmapScanProperties {

    /** nmap timespec: a positive number with an optional ms/s/m/h unit (e.g. "180s", "2m"). */
    private static final String NMAP_TIMESPEC = "^\\d+(\\.\\d+)?(ms|s|m|h)?$";

    @NotBlank
    @Pattern(regexp = NMAP_TIMESPEC, message = "must be an nmap timespec, e.g. 180s or 2m")
    private String portScanHostTimeout = "180s";

    @NotBlank
    @Pattern(regexp = NMAP_TIMESPEC, message = "must be an nmap timespec, e.g. 30s or 1m")
    private String pingHostTimeout = "30s";

    /**
     * Outer wall-clock cap on a single nmap process, applied via
     * {@link java.lang.Process#waitFor(long, java.util.concurrent.TimeUnit)} in
     * {@link NmapRunner}. On expiry the process is destroyed and the run fails with
     * {@code "nmap timed out"}. Distinct from the per-host {@code --host-timeout} passed
     * to nmap itself: this bounds the whole invocation across all targets. Default 300s
     * (sized for a /24 of mostly-dead hosts); raise via
     * {@code CASTELLUM_SCAN_NMAP_PROCESS_TIMEOUT_SECONDS} for larger ranges.
     */
    @Positive(message = "must be a positive number of seconds")
    private long processTimeoutSeconds = 300L;

    public String getPortScanHostTimeout() {
        return portScanHostTimeout;
    }

    public void setPortScanHostTimeout(String portScanHostTimeout) {
        this.portScanHostTimeout = portScanHostTimeout;
    }

    public String getPingHostTimeout() {
        return pingHostTimeout;
    }

    public void setPingHostTimeout(String pingHostTimeout) {
        this.pingHostTimeout = pingHostTimeout;
    }

    public long getProcessTimeoutSeconds() {
        return processTimeoutSeconds;
    }

    public void setProcessTimeoutSeconds(long processTimeoutSeconds) {
        this.processTimeoutSeconds = processTimeoutSeconds;
    }
}
