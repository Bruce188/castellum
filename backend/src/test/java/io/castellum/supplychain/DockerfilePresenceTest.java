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
    void finalStageUsesDistrolessAndNonroot() throws Exception {
        String body = Files.readString(dockerfile());
        assertTrue(body.contains("FROM gcr.io/distroless/java21-debian12"),
            "Dockerfile final stage must use gcr.io/distroless/java21-debian12");
        assertTrue(body.contains("USER nonroot"), "Dockerfile must include 'USER nonroot' directive");
    }
}
