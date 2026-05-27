package io.castellum.scan;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

@Component
@ConfigurationProperties(prefix = "castellum.scan.nmap")
@Validated
public class NmapScanProperties {

    @NotBlank
    private String portScanHostTimeout = "180s";

    @NotBlank
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
