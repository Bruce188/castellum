package io.castellum.discovery;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

class CaptureCapabilityProbeTest {

    @TempDir
    Path dir;

    private boolean isWsl(String osrelease) throws Exception {
        Path f = dir.resolve("osrelease");
        Files.writeString(f, osrelease);
        return new CaptureCapabilityProbe(f).isWsl();
    }

    @Test
    void wsl2KernelIsDetected() throws Exception {
        assertThat(isWsl("5.15.167.4-microsoft-standard-WSL2\n")).isTrue();
        assertThat(isWsl("4.4.0-19041-Microsoft\n")).isTrue();
    }

    @Test
    void nativeLinuxKernelIsNotWsl() throws Exception {
        assertThat(isWsl("6.8.0-45-generic\n")).isFalse();
    }

    @Test
    void missingOsreleaseIsNotWsl() {
        assertThat(new CaptureCapabilityProbe(dir.resolve("absent")).isWsl()).isFalse();
    }
}
