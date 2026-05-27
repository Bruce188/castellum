package io.castellum.scan;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
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
}
