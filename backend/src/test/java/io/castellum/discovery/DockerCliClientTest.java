package io.castellum.discovery;

import io.castellum.discovery.DockerCliClient.CommandResult;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link DockerCliClient} using a stubbed {@link DockerCliClient.CommandRunner}
 * so no real {@code docker} process is spawned. Verifies argv assembly, stdout parsing, the
 * empty-id short-circuit, and {@link DiscoveryUnavailableException} mapping for failure modes.
 */
class DockerCliClientTest {

    /** Records the argv it was handed and returns a canned result. */
    private static final class StubRunner implements DockerCliClient.CommandRunner {
        final List<List<String>> invocations = new ArrayList<>();
        private final CommandResult result;

        StubRunner(CommandResult result) {
            this.result = result;
        }

        @Override
        public CommandResult run(List<String> argv) {
            invocations.add(List.copyOf(argv));
            return result;
        }
    }

    @Test
    void listRunningContainerIds_parsesNonTruncatedIds() throws Exception {
        StubRunner runner = new StubRunner(new CommandResult(0, "abc123\ndef456\n", ""));
        DockerCliClient client = new DockerCliClient(runner);

        List<String> ids = client.listRunningContainerIds();

        assertThat(ids).containsExactly("abc123", "def456");
        // argv must be `docker ps -q --no-trunc`
        assertThat(runner.invocations).hasSize(1);
        assertThat(runner.invocations.get(0)).containsExactly("docker", "ps", "-q", "--no-trunc");
    }

    @Test
    void listRunningContainerIds_blankLinesIgnored() throws Exception {
        DockerCliClient client = new DockerCliClient(new StubRunner(new CommandResult(0, "\n  \nabc\n\n", "")));
        assertThat(client.listRunningContainerIds()).containsExactly("abc");
    }

    @Test
    void listRunningContainerIds_noContainers_emptyList() throws Exception {
        DockerCliClient client = new DockerCliClient(new StubRunner(new CommandResult(0, "", "")));
        assertThat(client.listRunningContainerIds()).isEmpty();
    }

    @Test
    void inspect_assemblesDockerInspectArgvWithIds() throws Exception {
        StubRunner runner = new StubRunner(new CommandResult(0, "[]", ""));
        DockerCliClient client = new DockerCliClient(runner);

        String out = client.inspect(List.of("abc", "def"));

        assertThat(out).isEqualTo("[]");
        assertThat(runner.invocations.get(0)).containsExactly("docker", "inspect", "--", "abc", "def");
    }

    @Test
    void inspect_emptyIds_shortCircuitsToEmptyArray_noSpawn() throws Exception {
        StubRunner runner = new StubRunner(new CommandResult(0, "SHOULD NOT BE RETURNED", ""));
        DockerCliClient client = new DockerCliClient(runner);

        assertThat(client.inspect(List.of())).isEqualTo("[]");
        assertThat(client.inspect(null)).isEqualTo("[]");
        // No process invoked for the empty case.
        assertThat(runner.invocations).isEmpty();
    }

    @Test
    void nonZeroExit_throwsDiscoveryUnavailableWithStderr() {
        DockerCliClient client = new DockerCliClient(
            new StubRunner(new CommandResult(1, "", "Cannot connect to the Docker daemon")));

        assertThatThrownBy(client::listRunningContainerIds)
            .isInstanceOf(DiscoveryUnavailableException.class)
            .hasMessageContaining("Cannot connect to the Docker daemon");
    }

    @Test
    void ioException_mappedToDiscoveryUnavailable() {
        DockerCliClient.CommandRunner throwing = argv -> { throw new IOException("docker: command not found"); };
        DockerCliClient client = new DockerCliClient(throwing);

        assertThatThrownBy(client::listRunningContainerIds)
            .isInstanceOf(DiscoveryUnavailableException.class)
            .hasMessageContaining("docker CLI unavailable");
    }
}
