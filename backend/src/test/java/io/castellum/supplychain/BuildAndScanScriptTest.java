package io.castellum.supplychain;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

class BuildAndScanScriptTest {
    private Path script() {
        Path p = Paths.get(System.getProperty("user.dir"), "scripts", "build-and-scan.sh");
        if (!p.toFile().exists()) {
            p = Paths.get(System.getProperty("user.dir"), "..", "scripts", "build-and-scan.sh").normalize();
        }
        return p;
    }

    @Test
    void scriptExistsAndIsExecutable() {
        Path s = script();
        assertTrue(Files.exists(s), "scripts/build-and-scan.sh must exist at " + s);
        assertTrue(Files.isExecutable(s), "scripts/build-and-scan.sh must be executable");
    }

    @Test
    void scriptReferencesTrivyAndCosign() throws Exception {
        String body = Files.readString(script());
        assertTrue(body.contains("trivy image"), "script must invoke trivy image");
        assertTrue(body.contains("--severity HIGH,CRITICAL"), "script must gate on HIGH,CRITICAL");
        assertTrue(body.contains("--exit-code 1"),
            "build-and-scan.sh must invoke trivy with --exit-code 1 to fail on findings");
        assertTrue(body.contains("cosign verify"), "script must reference cosign verify");
    }
}
