package io.castellum.ot.bacnet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * ASHRAE BACnet vendor-id → vendor-name registry.
 *
 * <p>Loaded from {@code /ot/bacnet-vendor-ids.csv} at class initialization.
 * Each line: {@code vendorId,vendorName}.
 * Updates are a follow-up; CSV format keeps the data greppable.
 */
public final class BacnetVendorRegistry {

    private static final Logger log = LoggerFactory.getLogger(BacnetVendorRegistry.class);

    private static final Map<Integer, String> REGISTRY = loadRegistry();

    private BacnetVendorRegistry() {}

    /**
     * Returns the ASHRAE-registered vendor name for the given numeric vendor id.
     *
     * @param vendorId BACnet numeric vendor id
     * @return vendor name, or empty if unknown
     */
    public static Optional<String> nameFor(int vendorId) {
        return Optional.ofNullable(REGISTRY.get(vendorId));
    }

    private static Map<Integer, String> loadRegistry() {
        Map<Integer, String> map = new HashMap<>(1200);
        String resourcePath = "/ot/bacnet-vendor-ids.csv";
        try (InputStream is = BacnetVendorRegistry.class.getResourceAsStream(resourcePath)) {
            if (is == null) {
                log.warn("BACnet vendor registry not found at {}; vendor lookup will return empty", resourcePath);
                return Collections.emptyMap();
            }
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                String line;
                int lineNum = 0;
                while ((line = reader.readLine()) != null) {
                    lineNum++;
                    if (line.isBlank() || line.startsWith("#")) continue;
                    int commaIdx = line.indexOf(',');
                    if (commaIdx < 1) continue;
                    String idStr = line.substring(0, commaIdx).trim();
                    String name = line.substring(commaIdx + 1).trim();
                    try {
                        map.put(Integer.parseInt(idStr), name);
                    } catch (NumberFormatException e) {
                        log.debug("Skipping invalid vendor-id at line {}: '{}'", lineNum, idStr);
                    }
                }
            }
        } catch (IOException e) {
            log.warn("Failed to load BACnet vendor registry: {}", e.getMessage());
        }
        return Collections.unmodifiableMap(map);
    }
}
