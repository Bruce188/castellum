package io.castellum.discovery;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.function.Supplier;

/**
 * Selects the appropriate {@link ArpReader} implementation for the host OS.
 *
 * <p>Selection rule (case-insensitive on {@code os.name}):
 * <ul>
 *   <li>contains {@code "win"} → {@link WindowsArpReader}</li>
 *   <li>contains {@code "mac"} → {@link MacArpReader}</li>
 *   <li>otherwise → {@link LinuxArpReader} (with WARN log if neither {@code linux} nor {@code nix})</li>
 * </ul>
 *
 * <p>The {@link Supplier}-based {@code os.name} indirection exists so tests can stub the OS
 * detection without mucking with the JVM system properties globally.
 */
@Component
public class ArpReaderFactory {

    private static final Logger log = LoggerFactory.getLogger(ArpReaderFactory.class);

    private final LinuxArpReader linux;
    private final WindowsArpReader windows;
    private final MacArpReader mac;
    private final Supplier<String> osNameSupplier;

    @Autowired
    public ArpReaderFactory(LinuxArpReader linux, WindowsArpReader windows, MacArpReader mac) {
        this(linux, windows, mac, () -> System.getProperty("os.name", "").toLowerCase());
    }

    /** Package-private testing seam — inject a stub OS-name supplier. */
    ArpReaderFactory(LinuxArpReader linux, WindowsArpReader windows, MacArpReader mac,
                     Supplier<String> osNameSupplier) {
        this.linux = linux;
        this.windows = windows;
        this.mac = mac;
        this.osNameSupplier = osNameSupplier;
    }

    /** Returns the {@link ArpReader} matching the current OS. Never returns null. */
    public ArpReader select() {
        String os = osNameSupplier.get();
        if (os.contains("win")) return windows;
        if (os.contains("mac")) return mac;
        if (!os.contains("linux") && !os.contains("nix")) {
            log.warn("Unrecognized os.name='{}'; falling back to LinuxArpReader", os);
        }
        return linux;
    }
}
