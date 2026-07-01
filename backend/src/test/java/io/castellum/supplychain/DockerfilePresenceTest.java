package io.castellum.supplychain;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

class DockerfilePresenceTest {
    private Path dockerfile() {
        Path p = Paths.get(System.getProperty("user.dir"), "Dockerfile");
        if (!p.toFile().exists()) {
            p = Paths.get(System.getProperty("user.dir"), "..", "Dockerfile").normalize();
        }
        return p;
    }

    @Test
    void dockerfileExistsAtRepoRoot() {
        assertTrue(Files.exists(dockerfile()), "Dockerfile must exist at repo root: " + dockerfile());
    }

    @Test
    void finalStageIsMinimalJreAndNonroot() throws Exception {
        String body = Files.readString(dockerfile());
        // The runtime base was moved off distroless to a slim JRE so the image can ship nmap +
        // libpcap — the active scanner and pcap discovery (the product's core features) are
        // non-functional without them. Keep it a *JRE* (not a full JDK) and pin the OS so the
        // swap can't silently regress to a heavier or looser base.
        assertTrue(body.contains("FROM eclipse-temurin:21-jre-noble"),
            "Dockerfile runtime stage must use the pinned slim JRE base eclipse-temurin:21-jre-noble");
        // Non-root is non-negotiable for an image that actively scans networks.
        assertTrue(body.contains("USER app"), "Dockerfile must drop to the non-root 'app' user");
        assertTrue(body.contains("--uid 65532"), "the runtime user must be the non-root uid 65532");
        // Keep the added attack surface minimal when installing the scanner dependencies.
        assertTrue(body.contains("--no-install-recommends"),
            "apt installs must use --no-install-recommends to keep the image minimal");
    }
}
