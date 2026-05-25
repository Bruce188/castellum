package io.castellum.security;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link RemoteAddrProvider} and {@link XForwardedForProvider}.
 */
class ClientAddressResolverTest {

    // ── RemoteAddrProvider ────────────────────────────────────────────────────

    @Test
    void remoteAddrProvider_returnsRemoteAddr() {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setRemoteAddr("10.0.0.1");
        req.addHeader("X-Forwarded-For", "203.0.113.5");

        ClientAddressResolver resolver = new RemoteAddrProvider();
        assertEquals("10.0.0.1", resolver.resolve(req),
                "RemoteAddrProvider must ignore X-Forwarded-For");
    }

    @Test
    void remoteAddrProvider_returnsNullRemoteAddr_whenNoneSet() {
        MockHttpServletRequest req = new MockHttpServletRequest();
        ClientAddressResolver resolver = new RemoteAddrProvider();
        // MockHttpServletRequest defaults remoteAddr to "127.0.0.1"
        assertEquals("127.0.0.1", resolver.resolve(req));
    }

    // ── XForwardedForProvider — trusted proxy ─────────────────────────────────

    @Test
    void xffProvider_trustedProxy_returnsFirstXffIp() {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setRemoteAddr("10.0.0.254"); // trusted proxy within 10.0.0.0/24
        req.addHeader("X-Forwarded-For", "203.0.113.7, 10.0.0.100");

        ClientAddressResolver resolver = new XForwardedForProvider(
                List.of("10.0.0.0/24"), "10.0.0.254");
        assertEquals("203.0.113.7", resolver.resolve(req),
                "XFF provider must return the first IP in the XFF header when proxy is trusted");
    }

    @Test
    void xffProvider_untrustedProxy_returnsRemoteAddr() {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setRemoteAddr("1.2.3.4"); // NOT in trusted list
        req.addHeader("X-Forwarded-For", "203.0.113.7");

        ClientAddressResolver resolver = new XForwardedForProvider(
                List.of("10.0.0.0/24"), "1.2.3.4");
        assertEquals("1.2.3.4", resolver.resolve(req),
                "XFF provider must fall back to remoteAddr when proxy is not trusted");
    }

    @Test
    void xffProvider_missingXffHeader_returnsRemoteAddr() {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setRemoteAddr("10.0.0.1");

        ClientAddressResolver resolver = new XForwardedForProvider(
                List.of("10.0.0.0/24"), "10.0.0.1");
        assertEquals("10.0.0.1", resolver.resolve(req),
                "XFF provider must fall back to remoteAddr when X-Forwarded-For is absent");
    }

    @Test
    void xffProvider_emptyXffHeader_returnsRemoteAddr() {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setRemoteAddr("10.0.0.1");
        req.addHeader("X-Forwarded-For", "");

        ClientAddressResolver resolver = new XForwardedForProvider(
                List.of("10.0.0.0/24"), "10.0.0.1");
        assertEquals("10.0.0.1", resolver.resolve(req),
                "XFF provider must fall back to remoteAddr when X-Forwarded-For is empty");
    }

    @Test
    void xffProvider_multipleXffValues_returnsFirst() {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setRemoteAddr("192.168.1.1"); // trusted /24
        req.addHeader("X-Forwarded-For", "198.51.100.1, 172.16.0.1, 10.0.0.2");

        ClientAddressResolver resolver = new XForwardedForProvider(
                List.of("192.168.1.0/24"), "192.168.1.1");
        assertEquals("198.51.100.1", resolver.resolve(req),
                "XFF provider must return the leftmost (client-originating) IP");
    }

    // ── XForwardedForProvider — IPv4 CIDR boundaries ─────────────────────────

    @Test
    void xffProvider_hostRoute_exact32BitMatch() {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setRemoteAddr("172.16.0.5");
        req.addHeader("X-Forwarded-For", "8.8.8.8");

        ClientAddressResolver resolver = new XForwardedForProvider(
                List.of("172.16.0.5/32"), "172.16.0.5");
        assertEquals("8.8.8.8", resolver.resolve(req),
                "/32 CIDR must match the exact host address");
    }

    @Test
    void xffProvider_hostRoute_nonMatchingAddress() {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setRemoteAddr("172.16.0.6");
        req.addHeader("X-Forwarded-For", "8.8.8.8");

        ClientAddressResolver resolver = new XForwardedForProvider(
                List.of("172.16.0.5/32"), "172.16.0.6");
        assertEquals("172.16.0.6", resolver.resolve(req),
                "/32 CIDR must not match an adjacent address");
    }

    // ── Invalid CIDR at construction time ────────────────────────────────────

    @Test
    void xffProvider_invalidCidr_throwsAtConstruction() {
        assertThrows(IllegalArgumentException.class,
                () -> new XForwardedForProvider(List.of("not-a-cidr"), "10.0.0.1"),
                "invalid CIDR must throw IllegalArgumentException at construction");
    }
}
