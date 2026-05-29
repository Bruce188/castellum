package io.castellum.scan;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class NmapScanPropertiesTest {

    @Test
    void defaults_areSetWhenNotOverridden() {
        NmapScanProperties props = new NmapScanProperties();
        assertEquals("180s", props.getPortScanHostTimeout(),
            "default portScanHostTimeout must be 180s");
        assertEquals("30s", props.getPingHostTimeout(),
            "default pingHostTimeout must be 30s");
        assertEquals(300L, props.getProcessTimeoutSeconds(),
            "default processTimeoutSeconds must be 300 (sized for a /24, preserving prior behaviour)");
    }

    @Test
    void settersRoundTrip() {
        NmapScanProperties props = new NmapScanProperties();
        props.setPortScanHostTimeout("300s");
        props.setPingHostTimeout("60s");
        props.setProcessTimeoutSeconds(900L);
        assertEquals("300s", props.getPortScanHostTimeout());
        assertEquals("60s", props.getPingHostTimeout());
        assertEquals(900L, props.getProcessTimeoutSeconds());
    }

    @Test
    void defaultTimeoutTokens_areShellMetaClean() {
        NmapScanProperties props = new NmapScanProperties();
        for (String token : new String[]{props.getPortScanHostTimeout(), props.getPingHostTimeout()}) {
            assertFalse(token.contains(" "), token + " contains space");
            assertFalse(token.contains(";"), token + " contains semicolon");
            assertFalse(token.contains("&"), token + " contains ampersand");
            assertFalse(token.contains("|"), token + " contains pipe");
            assertFalse(token.contains("$"), token + " contains dollar");
            assertFalse(token.contains("`"), token + " contains backtick");
        }
    }
}
