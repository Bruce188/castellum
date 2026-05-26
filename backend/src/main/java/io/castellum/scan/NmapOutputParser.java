package io.castellum.scan;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Pure-function stdout parser for nmap output.
 *
 * <p>Accepts nmap's text-format stdout and extracts discovered hosts and open
 * services. Lines that do not match any recognised pattern are silently skipped
 * (defensive — nmap output formats vary by version and flags).
 *
 * <p>No Spring dependencies are invoked; no repositories are touched. This class
 * is used exclusively by {@code ScanExecutionService}.
 */
@Component
public class NmapOutputParser {

    // -----------------------------------------------------------------------
    // Output record types (local to this class; ScanExecutionService maps them
    // to Discovery / NetworkService domain objects).
    // -----------------------------------------------------------------------

    /** A discovered host from nmap output. */
    public record DiscoveredHost(String ipAddress, String hostname) {}

    /** A discovered open port/service from nmap output. */
    public record DiscoveredService(String ipAddress, int port, String protocol, String name, String version) {}

    /** Parser result container. */
    public record ParsedScan(List<DiscoveredHost> hosts, List<DiscoveredService> services) {}

    // -----------------------------------------------------------------------
    // Patterns
    // -----------------------------------------------------------------------

    /**
     * Matches "Nmap scan report for" lines, capturing optional hostname and IP.
     * Formats:
     *   Nmap scan report for 192.168.1.1
     *   Nmap scan report for myhost (192.168.1.1)
     */
    private static final Pattern REPORT_PATTERN = Pattern.compile(
        "Nmap scan report for (?:([\\w.-]+) \\((\\d+\\.\\d+\\.\\d+\\.\\d+)\\)|(\\d+\\.\\d+\\.\\d+\\.\\d+))");

    /**
     * Matches "Host is up" lines confirming the host responded to ping.
     */
    private static final Pattern HOST_UP_PATTERN = Pattern.compile("Host is up");

    /**
     * Matches open port lines from service detection (-sV).
     * Format: PORT/PROTO STATE SERVICE VERSION
     * Example: 22/tcp open ssh OpenSSH 8.2p1
     */
    private static final Pattern PORT_PATTERN = Pattern.compile(
        "^(\\d+)/(tcp|udp)\\s+open\\s+(\\S+)(?:\\s+(.*))?$");

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /**
     * Parse nmap stdout into discovered hosts and services.
     *
     * @param stdout  raw stdout string from {@link NmapResult#stdout()}
     * @param type    the scan type (affects whether service lines are expected)
     * @return parsed result; never null; empty lists when no hosts found
     */
    public ParsedScan parse(String stdout, ScanType type) {
        List<DiscoveredHost> hosts = new ArrayList<>();
        List<DiscoveredService> services = new ArrayList<>();

        if (stdout == null || stdout.isBlank()) {
            return new ParsedScan(hosts, services);
        }

        String currentIp = null;
        String currentHostname = null;
        boolean hostUp = false;

        for (String line : stdout.split("\\r?\\n")) {
            String trimmed = line.trim();

            // "Nmap scan report for ..." — new host block begins
            Matcher reportMatcher = REPORT_PATTERN.matcher(trimmed);
            if (reportMatcher.find()) {
                // Flush previous host if it was up
                if (hostUp && currentIp != null) {
                    hosts.add(new DiscoveredHost(currentIp, currentHostname));
                }
                // Reset state for new host
                hostUp = false;
                if (reportMatcher.group(3) != null) {
                    // IP-only format: no hostname
                    currentIp = reportMatcher.group(3);
                    currentHostname = null;
                } else {
                    // hostname (IP) format
                    currentHostname = reportMatcher.group(1);
                    currentIp = reportMatcher.group(2);
                }
                continue;
            }

            // "Host is up" — mark current host as alive
            if (HOST_UP_PATTERN.matcher(trimmed).find()) {
                hostUp = true;
                // For ping-sweep, mark the host immediately since no port lines follow
                if (type == ScanType.PING_SWEEP && currentIp != null) {
                    hosts.add(new DiscoveredHost(currentIp, currentHostname));
                    hostUp = false; // consumed
                    currentIp = null;
                    currentHostname = null;
                }
                continue;
            }

            // Port/service lines — only meaningful for SERVICE_DETECT / OS_FINGERPRINT
            if (currentIp != null && type != ScanType.PING_SWEEP) {
                Matcher portMatcher = PORT_PATTERN.matcher(trimmed);
                if (portMatcher.matches()) {
                    int port = Integer.parseInt(portMatcher.group(1));
                    String protocol = portMatcher.group(2);
                    String name = portMatcher.group(3);
                    String rawVersion = portMatcher.group(4);
                    String version = (rawVersion != null) ? rawVersion.trim() : "";
                    services.add(new DiscoveredService(currentIp, port, protocol, name, version));
                }
            }
        }

        // Flush last host for SERVICE_DETECT / OS_FINGERPRINT (hostUp set but not yet flushed)
        if (hostUp && currentIp != null) {
            hosts.add(new DiscoveredHost(currentIp, currentHostname));
        }

        return new ParsedScan(hosts, services);
    }
}
