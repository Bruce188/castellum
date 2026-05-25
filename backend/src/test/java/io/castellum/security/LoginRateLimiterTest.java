package io.castellum.security;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.*;

class LoginRateLimiterTest {

    private static final Instant BASE = Instant.parse("2025-01-01T00:00:00Z");

    private LoginRateLimiter limiter(Clock clock, long windowSeconds, int maxAttempts) {
        return new LoginRateLimiter(windowSeconds, maxAttempts, clock);
    }

    private Clock fixed(Instant instant) {
        return Clock.fixed(instant, ZoneOffset.UTC);
    }

    private Clock offset(Clock base, Duration d) {
        return Clock.offset(base, d);
    }

    // ── basic permit/deny ─────────────────────────────────────────────────────

    @Test
    void freshIpIsPermitted() {
        LoginRateLimiter rl = limiter(fixed(BASE), 60, 5);
        assertTrue(rl.tryAcquire("10.0.0.1"), "first attempt must be permitted");
    }

    @Test
    void attemptsUpToMaxArePermitted() {
        Clock clock = fixed(BASE);
        LoginRateLimiter rl = limiter(clock, 60, 3);
        // record 2 failures: still 1 slot left
        rl.recordFailure("10.0.0.1");
        rl.recordFailure("10.0.0.1");
        assertTrue(rl.tryAcquire("10.0.0.1"), "attempt below max must be permitted");
    }

    @Test
    void exceedingMaxIsDenied() {
        Clock clock = fixed(BASE);
        LoginRateLimiter rl = limiter(clock, 60, 3);
        rl.recordFailure("10.0.0.1");
        rl.recordFailure("10.0.0.1");
        rl.recordFailure("10.0.0.1");
        assertFalse(rl.tryAcquire("10.0.0.1"), "attempt at max must be denied");
    }

    // ── sliding-window prune ──────────────────────────────────────────────────

    @Test
    void expiredAttemptsArePruned() {
        Clock t0 = fixed(BASE);
        LoginRateLimiter rl = limiter(t0, 60, 3);
        rl.recordFailure("10.0.0.2");
        rl.recordFailure("10.0.0.2");
        rl.recordFailure("10.0.0.2");
        assertFalse(rl.tryAcquire("10.0.0.2"), "should be denied before window expires");

        // Advance past the window — failures are now outside the 60-second window
        Clock t1 = offset(t0, Duration.ofSeconds(61));
        LoginRateLimiter rlLater = new LoginRateLimiter(60, 3, t1);
        // Different instance, but same scenario with fresh data
        rlLater.recordFailure("10.0.0.2");
        rlLater.recordFailure("10.0.0.2");
        rlLater.recordFailure("10.0.0.2");
        assertFalse(rlLater.tryAcquire("10.0.0.2"));

        // Test pruning via a single instance by advancing the clock reference
        // Use a mutable clock holder
        Clock[] clocks = {t0};
        LoginRateLimiter pruneRl = new LoginRateLimiter(60, 3,
                new Clock() {
                    @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
                    @Override public Clock withZone(java.time.ZoneId zone) { return clocks[0].withZone(zone); }
                    @Override public Instant instant() { return clocks[0].instant(); }
                });
        pruneRl.recordFailure("10.0.0.3");
        pruneRl.recordFailure("10.0.0.3");
        pruneRl.recordFailure("10.0.0.3");
        assertFalse(pruneRl.tryAcquire("10.0.0.3"), "denied at max");

        // Advance clock beyond window
        clocks[0] = offset(t0, Duration.ofSeconds(61));
        assertTrue(pruneRl.tryAcquire("10.0.0.3"), "denied entries expired; must be permitted after window");
    }

    @Test
    void partialExpiryPrunesOnlyOldEntries() {
        Clock[] clocks = {fixed(BASE)};
        Clock proxy = new Clock() {
            @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
            @Override public Clock withZone(java.time.ZoneId zone) { return clocks[0].withZone(zone); }
            @Override public Instant instant() { return clocks[0].instant(); }
        };
        LoginRateLimiter rl = limiter(proxy, 60, 5);

        // 2 failures at t=0
        rl.recordFailure("10.0.0.4");
        rl.recordFailure("10.0.0.4");

        // advance 50 seconds, add 2 more failures
        clocks[0] = offset(fixed(BASE), Duration.ofSeconds(50));
        rl.recordFailure("10.0.0.4");
        rl.recordFailure("10.0.0.4");

        // advance 61 seconds from BASE — the t=0 entries are pruned (>60s), the t=50 entries are not
        clocks[0] = offset(fixed(BASE), Duration.ofSeconds(61));
        // 2 entries remain (recorded at t=50, now only 11s old)
        assertTrue(rl.tryAcquire("10.0.0.4"), "only 2 unexpired entries remain; 5-attempt budget allows it");
    }

    // ── retryAfterSeconds math ────────────────────────────────────────────────

    @Test
    void retryAfterIsZeroWhenNoPriorFailures() {
        LoginRateLimiter rl = limiter(fixed(BASE), 60, 5);
        assertEquals(0L, rl.retryAfterSeconds("10.0.0.5"));
    }

    @Test
    void retryAfterReflectsWindowRemaining() {
        Clock[] clocks = {fixed(BASE)};
        Clock proxy = new Clock() {
            @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
            @Override public Clock withZone(java.time.ZoneId zone) { return clocks[0].withZone(zone); }
            @Override public Instant instant() { return clocks[0].instant(); }
        };
        LoginRateLimiter rl = limiter(proxy, 60, 2);
        rl.recordFailure("10.0.0.6");
        rl.recordFailure("10.0.0.6");

        // At t=0 oldest is at t=0, so remaining = 60 - 0 = 60
        assertEquals(60L, rl.retryAfterSeconds("10.0.0.6"));

        // At t=30 remaining = 60 - 30 = 30
        clocks[0] = offset(fixed(BASE), Duration.ofSeconds(30));
        assertEquals(30L, rl.retryAfterSeconds("10.0.0.6"));
    }

    @Test
    void retryAfterIsAtLeastOneSecond() {
        Clock[] clocks = {fixed(BASE)};
        Clock proxy = new Clock() {
            @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
            @Override public Clock withZone(java.time.ZoneId zone) { return clocks[0].withZone(zone); }
            @Override public Instant instant() { return clocks[0].instant(); }
        };
        LoginRateLimiter rl = limiter(proxy, 60, 2);
        rl.recordFailure("10.0.0.7");
        rl.recordFailure("10.0.0.7");

        // Advance to exactly the window boundary (60 s) — remaining would be 0 but clamped to 1
        clocks[0] = offset(fixed(BASE), Duration.ofSeconds(60));
        assertEquals(1L, rl.retryAfterSeconds("10.0.0.7"),
                "retryAfterSeconds must be >= 1 even at the window boundary");
    }

    // ── independent IP isolation ──────────────────────────────────────────────

    @Test
    void differentIpsAreTrackedIndependently() {
        Clock clock = fixed(BASE);
        LoginRateLimiter rl = limiter(clock, 60, 2);
        rl.recordFailure("10.0.0.8");
        rl.recordFailure("10.0.0.8");
        assertFalse(rl.tryAcquire("10.0.0.8"), "ip-A exhausted");
        assertTrue(rl.tryAcquire("10.0.0.9"), "ip-B unaffected by ip-A failures");
    }

    // ── parallel-stream concurrency ───────────────────────────────────────────

    @Test
    void concurrentRecordFailuresDoNotExceedCapacity() throws Exception {
        Clock clock = fixed(BASE);
        LoginRateLimiter rl = limiter(clock, 60, 10);
        int threads = 20;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            futures.add(pool.submit(() -> rl.recordFailure("10.0.1.1")));
        }
        for (Future<?> f : futures) {
            f.get();
        }
        pool.shutdown();

        // The deque may have up to 20 entries; what matters is that tryAcquire → false
        // (capacity exceeded) and no exception was thrown (no race corruption)
        assertFalse(rl.tryAcquire("10.0.1.1"),
                "after 20 concurrent failures the ip must be rate-limited");
    }
}
