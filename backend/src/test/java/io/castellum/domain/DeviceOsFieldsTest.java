package io.castellum.domain;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DeviceOsFieldsTest {

    @Test
    void device_osFields_roundTripViaGettersSetters() {
        Device d = new Device();

        d.setOsName("Linux 5.4 - 5.15");
        d.setOsAccuracy(96);
        d.setOsCpe("cpe:/o:linux:linux_kernel:5");

        assertEquals("Linux 5.4 - 5.15", d.getOsName());
        assertEquals(96, d.getOsAccuracy());
        assertEquals("cpe:/o:linux:linux_kernel:5", d.getOsCpe());
    }
}
