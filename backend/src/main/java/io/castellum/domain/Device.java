package io.castellum.domain;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "device")
public class Device {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "ip_address", nullable = false, unique = true)
    private String ipAddress;

    private String hostname;

    @Column(name = "mac_address")
    private String macAddress;

    @Column(name = "first_seen")
    private Instant firstSeen;

    @Column(name = "last_seen")
    private Instant lastSeen;

    public Device() {}

    public Device(Long id, String ipAddress, String hostname, String macAddress, Instant firstSeen, Instant lastSeen) {
        this.id = id;
        this.ipAddress = ipAddress;
        this.hostname = hostname;
        this.macAddress = macAddress;
        this.firstSeen = firstSeen;
        this.lastSeen = lastSeen;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getIpAddress() { return ipAddress; }
    public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }

    public String getHostname() { return hostname; }
    public void setHostname(String hostname) { this.hostname = hostname; }

    public String getMacAddress() { return macAddress; }
    public void setMacAddress(String macAddress) { this.macAddress = macAddress; }

    public Instant getFirstSeen() { return firstSeen; }
    public void setFirstSeen(Instant firstSeen) { this.firstSeen = firstSeen; }

    public Instant getLastSeen() { return lastSeen; }
    public void setLastSeen(Instant lastSeen) { this.lastSeen = lastSeen; }
}
