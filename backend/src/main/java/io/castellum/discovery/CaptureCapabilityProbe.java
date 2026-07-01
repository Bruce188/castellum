package io.castellum.discovery;

import org.pcap4j.core.Pcaps;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Boot-time capability probe. Warns once (never fatally) when this runtime cannot actually
 * run active nmap scans or pcap4j passive capture, so a CVE-only deployment still boots but
 * an operator expecting scanning is not left guessing why every source comes back empty.
 *
 * <p>Three real runtime signals are checked: nmap on {@code PATH} (how {@code NmapRunner}
 * resolves the binary), libpcap loadable (the pcap4j → JNA native path), and {@code CAP_NET_RAW}
 * held by the process (raw-socket open). A single WARN names the gaps and the remedy.
 */
@Component
public class CaptureCapabilityProbe {

    private static final Logger log = LoggerFactory.getLogger(CaptureCapabilityProbe.class);

    /** CAP_NET_RAW is capability bit 13 in the Linux capability bitmask (linux/capability.h). */
    private static final int CAP_NET_RAW = 13;

    @EventListener(ApplicationReadyEvent.class)
    public void probe() {
        List<String> missing = new ArrayList<>();
        if (!nmapOnPath()) missing.add("nmap not found on PATH (active scanning disabled)");
        if (!libpcapLoadable()) missing.add("libpcap not loadable (PCAP/LLDP/CDP capture disabled)");
        if (!hasCapNetRaw()) missing.add("CAP_NET_RAW not held by this process (raw-socket capture and nmap -sS/-sn/-O will fail)");

        if (missing.isEmpty()) {
            log.debug("Capture capability probe: nmap, libpcap and CAP_NET_RAW all present");
            return;
        }
        log.warn("Network scanning and passive capture are INERT in this runtime: {}. "
                + "Affected sources return nothing silently; CVE-only deployments without scanning can ignore this. "
                + "Remedy: run the container with --network=host and grant raw sockets "
                + "(docker --cap-add=NET_RAW), and on the nmap binary "
                + "`setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap`.",
                String.join("; ", missing));
    }

    /** Mirrors {@code NmapRunner}, which spawns the bare {@code nmap} resolved via PATH. */
    private static boolean nmapOnPath() {
        String path = System.getenv("PATH");
        if (path == null) return false;
        for (String dir : path.split(File.pathSeparator)) {
            if (!dir.isBlank() && new File(dir, "nmap").canExecute()) return true;
        }
        return false;
    }

    /** {@code Pcaps.libVersion()} forces JNA to load libpcap; a missing .so surfaces as an Error. */
    private static boolean libpcapLoadable() {
        try {
            Pcaps.libVersion();
            return true;
        } catch (Throwable t) { // ponytail: absent native lib is UnsatisfiedLinkError (an Error), not an Exception
            return false;
        }
    }

    /**
     * Tests the process's effective CAP_NET_RAW via {@code /proc/self/status}. This covers both a
     * root process and a {@code --cap-add=NET_RAW} container; the nmap binary's own file caps
     * (set via {@code setcap}) are not readable from Java without {@code getcap}, so the remedy
     * names them instead. Returns false off Linux / when procfs is unavailable.
     */
    private static boolean hasCapNetRaw() {
        try {
            for (String line : Files.readAllLines(Path.of("/proc/self/status"))) {
                if (line.startsWith("CapEff:")) {
                    long eff = Long.parseUnsignedLong(line.substring(7).trim(), 16);
                    return (eff & (1L << CAP_NET_RAW)) != 0;
                }
            }
        } catch (Throwable t) { // ponytail: non-Linux / no procfs → capability cannot be confirmed
            return false;
        }
        return false;
    }
}
