package io.castellum.risk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class CompositeScorerGoldenTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Path GOLDEN_DIR = Paths.get("src/test/resources/risk/golden");

    @ParameterizedTest(name = "{0}")
    @MethodSource("allFixtures")
    void goldenCases(String name, RiskInputs inputs, double expected, double tolerance) {
        var actual = CompositeScorer.score(inputs);
        assertThat(actual.score().doubleValue())
            .as("fixture %s: input=%s expected=%.2f ± %.2f got=%s",
                name, inputs, expected, tolerance, actual.score())
            .isCloseTo(expected, org.assertj.core.data.Offset.offset(tolerance));
    }

    static Stream<Arguments> allFixtures() throws Exception {
        List<Path> files;
        try (var stream = Files.list(GOLDEN_DIR)) {
            files = stream
                .filter(p -> p.toString().endsWith(".json"))
                .sorted()
                .toList();
        }
        if (files.isEmpty()) {
            throw new IllegalStateException("No golden fixtures found in " + GOLDEN_DIR.toAbsolutePath());
        }
        return files.stream().map(p -> {
            try {
                JsonNode root = MAPPER.readTree(p.toFile());
                String name = root.get("name").asText();
                JsonNode input = root.get("input");
                RiskInputs inputs = new RiskInputs(
                    input.get("cvssNormalized").asDouble(),
                    input.get("epss").asDouble(),
                    input.get("kev").asBoolean(),
                    Criticality.valueOf(input.get("criticality").asText()));
                double expected = root.get("expectedScore").asDouble();
                double tolerance = root.get("tolerance").asDouble();
                return Arguments.of(name, inputs, expected, tolerance);
            } catch (Exception e) {
                throw new RuntimeException("Failed to load fixture " + p, e);
            }
        });
    }
}
