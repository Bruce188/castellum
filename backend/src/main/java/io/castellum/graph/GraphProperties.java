package io.castellum.graph;

import jakarta.validation.constraints.Min;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

@Component
@ConfigurationProperties(prefix = "castellum.graph")
@Validated
public class GraphProperties {

    @Min(1)
    private int subnetCap = 64;

    @Min(1)
    private int vulnsPerPairCap = 5;

    @Min(1)
    private int maxDevices = 1024;

    public int getSubnetCap() { return subnetCap; }
    public void setSubnetCap(int subnetCap) { this.subnetCap = subnetCap; }

    public int getVulnsPerPairCap() { return vulnsPerPairCap; }
    public void setVulnsPerPairCap(int vulnsPerPairCap) { this.vulnsPerPairCap = vulnsPerPairCap; }

    public int getMaxDevices() { return maxDevices; }
    public void setMaxDevices(int maxDevices) { this.maxDevices = maxDevices; }
}
