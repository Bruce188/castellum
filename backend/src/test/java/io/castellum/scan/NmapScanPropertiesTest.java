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
    }

    @Test
    void settersRoundTrip() {
        NmapScanProperties props = new NmapScanProperties();
        props.setPortScanHostTimeout("300s");
        props.setPingHostTimeout("60s");
        assertEquals("300s", props.getPortScanHostTimeout());
        assertEquals("60s", props.getPingHostTimeout());
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
