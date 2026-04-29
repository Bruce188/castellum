package io.castellum.threatintel.stix;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SchemaValidatorsConfig;
import com.networknt.schema.SpecVersion;
import com.networknt.schema.ValidationMessage;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.List;
import java.util.Set;

/** Test-scope STIX 2.1 bundle validator. Loads OASIS schemas from classpath. */
public final class StixSchemaValidator {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final JsonSchema BUNDLE_SCHEMA = loadBundleSchema();

    private StixSchemaValidator() {}

    public static List<String> validate(String bundleJson) throws IOException {
        JsonNode root = MAPPER.readTree(bundleJson);
        Set<ValidationMessage> errors = BUNDLE_SCHEMA.validate(root);
        return errors.stream().map(ValidationMessage::getMessage).toList();
    }

    private static JsonSchema loadBundleSchema() {
        try {
            JsonSchemaFactory factory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012);
            try (InputStream in = StixSchemaValidator.class
                    .getResourceAsStream("/schemas/stix-2.1/bundle.json")) {
                if (in == null) throw new IllegalStateException("bundle.json not on classpath");
                return factory.getSchema(in);
            }
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load STIX bundle schema", e);
        }
    }
}
