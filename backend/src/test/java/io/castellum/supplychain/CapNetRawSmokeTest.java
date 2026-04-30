package io.castellum.supplychain;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.abort;

@EnabledIfSystemProperty(named = "castellum.cap-net-raw-smoke", matches = "true")
class CapNetRawSmokeTest {

    @Test
    void bootsWithCapNetRawOnly() throws Exception {
        assumeDockerAvailable();
        assumeImagePresent();

        ProcessBuilder pb = new ProcessBuilder(
            "docker", "run", "--rm",
            "--cap-drop=ALL", "--cap-add=NET_RAW",
            "castellum:latest");
        pb.redirectErrorStream(true);

        Process p = pb.start();
        boolean done = p.waitFor(45, TimeUnit.SECONDS);
        if (!done) {
            p.destroyForcibly();
            org.junit.jupiter.api.Assertions.fail("docker run timed out after 45s");
        }
        String stdout;
        try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
            stdout = r.lines().collect(Collectors.joining("\n"));
        }
        assertEquals(0, p.exitValue(),
            "container must exit 0 with only CAP_NET_RAW; output:\n" + stdout);
    }

    private static void assumeDockerAvailable() throws Exception {
        ProcessBuilder pb = new ProcessBuilder("docker", "--version");
        pb.redirectErrorStream(true);
        Process p;
        try {
            p = pb.start();
        } catch (Exception e) {
            abort("docker CLI unavailable — skip CAP_NET_RAW smoke test");
            return;
        }
        if (!p.waitFor(5, TimeUnit.SECONDS) || p.exitValue() != 0) {
            abort("docker --version failed — skip CAP_NET_RAW smoke test");
        }
    }

    private static void assumeImagePresent() throws Exception {
        ProcessBuilder pb = new ProcessBuilder(
            "docker", "image", "inspect", "castellum:latest");
        pb.redirectErrorStream(true);
        Process p = pb.start();
        if (!p.waitFor(5, TimeUnit.SECONDS) || p.exitValue() != 0) {
            abort("castellum:latest image not present — operator must `docker build` first");
        }
    }
}
