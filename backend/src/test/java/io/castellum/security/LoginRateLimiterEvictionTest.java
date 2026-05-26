package io.castellum.security;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies that {@link LoginRateLimiter#evictStaleEntries()} removes outer-map
 * keys whose deque is empty after pruning, preventing unbounded memory growth.
 */
class LoginRateLimiterEvictionTest {

    private static final Instant BASE = Instant.parse("2025-01-01T00:00:00Z");

    @Test
    void evictionRemovesEmptyDequesAfterWindowExpiry() {
        Clock[] clocks = {Clock.fixed(BASE, ZoneOffset.UTC)};
        Clock proxy = new Clock() {
            @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
            @Override public Clock withZone(java.time.ZoneId zone) { return clocks[0].withZone(zone); }
            @Override public Instant instant() { return clocks[0].instant(); }
        };

        LoginRateLimiter rl = new LoginRateLimiter(60, 5, proxy);
        rl.recordFailure("192.168.1.1");
        rl.recordFailure("192.168.1.2");

        // Both IPs have non-empty deques
        assertFalse(rl.tryAcquire("192.168.1.1") && rl.attempts().isEmpty(),
                "map should have entries before eviction");

        // Advance past window
        clocks[0] = Clock.offset(Clock.fixed(BASE, ZoneOffset.UTC), Duration.ofSeconds(61));

        // Before eviction: deques are empty when pruned, but keys still in map
        rl.evictStaleEntries();

        // After eviction: outer map is empty
        assertTrue(rl.attempts().isEmpty(),
                "outer map must be empty after evicting all stale IPs");
    }

    @Test
    void evictionPreservesActiveEntries() {
        Clock[] clocks = {Clock.fixed(BASE, ZoneOffset.UTC)};
        Clock proxy = new Clock() {
            @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
            @Override public Clock withZone(java.time.ZoneId zone) { return clocks[0].withZone(zone); }
            @Override public Instant instant() { return clocks[0].instant(); }
        };

        LoginRateLimiter rl = new LoginRateLimiter(60, 5, proxy);
        // ip-A: failure at t=0 (will expire after 60s)
        rl.recordFailure("10.0.0.1");

        // Advance 30s, add ip-B failure (will not expire at t=61)
        clocks[0] = Clock.offset(Clock.fixed(BASE, ZoneOffset.UTC), Duration.ofSeconds(30));
        rl.recordFailure("10.0.0.2");

        // Advance to t=61: ip-A's entry has expired, ip-B's hasn't
        clocks[0] = Clock.offset(Clock.fixed(BASE, ZoneOffset.UTC), Duration.ofSeconds(61));
        rl.evictStaleEntries();

        assertFalse(rl.attempts().containsKey("10.0.0.1"),
                "ip-A must be evicted (all entries expired)");
        assertTrue(rl.attempts().containsKey("10.0.0.2"),
                "ip-B must be retained (entry still within window)");
    }

    @Test
    void evictionOnEmptyMapIsNoOp() {
        LoginRateLimiter rl = new LoginRateLimiter(60, 5, Clock.fixed(BASE, ZoneOffset.UTC));
        assertDoesNotThrow(rl::evictStaleEntries, "eviction on empty map must not throw");
        assertTrue(rl.attempts().isEmpty());
    }
}
