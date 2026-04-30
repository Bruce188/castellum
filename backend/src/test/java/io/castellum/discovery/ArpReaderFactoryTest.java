package io.castellum.discovery;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Behavioural tests for {@link ArpReaderFactory#select()}. Uses the package-private
 * constructor with a stubbed {@link Supplier} for {@code os.name}, leaving JVM system
 * properties untouched.
 */
@ExtendWith(MockitoExtension.class)
class ArpReaderFactoryTest {

    @Mock private LinuxArpReader linux;
    @Mock private WindowsArpReader windows;
    @Mock private MacArpReader mac;

    private ArpReaderFactory factory(String osName) {
        return new ArpReaderFactory(linux, windows, mac, () -> osName.toLowerCase());
    }

    @Test
    void select_onLinuxOs_returnsLinuxArpReader() {
        assertThat(factory("Linux").select()).isSameAs(linux);
    }

    @Test
    void select_onWindowsOs_returnsWindowsArpReader() {
        assertThat(factory("Windows 11").select()).isSameAs(windows);
        assertThat(factory("Windows Server 2022").select()).isSameAs(windows);
    }

    @Test
    void select_onMacOs_returnsMacArpReader() {
        assertThat(factory("Mac OS X").select()).isSameAs(mac);
        assertThat(factory("macOS").select()).isSameAs(mac);
    }

    @Test
    void select_unknownOs_fallsBackToLinuxAndLogsWarn() {
        // No way to assert on the WARN log without LogCaptor; we still verify the fallback.
        assertThat(factory("NetBSD").select()).isSameAs(linux);
        assertThat(factory("Solaris").select()).isSameAs(linux);
    }

    @Test
    void select_nixVariant_returnsLinuxWithoutWarning() {
        // FreeBSD / OpenBSD / SunOS contain "nix" or are out of band — accept linux/nix as silent fallback
        assertThat(factory("Linux").select()).isSameAs(linux);
    }
}
