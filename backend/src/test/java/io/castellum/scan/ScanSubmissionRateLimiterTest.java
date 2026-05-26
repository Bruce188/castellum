package io.castellum.scan;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.*;

class ScanSubmissionRateLimiterTest {

    private static final Instant BASE = Instant.parse("2026-05-26T00:00:00Z");

    private Clock fixed(Instant instant) {
        return Clock.fixed(instant, ZoneOffset.UTC);
    }

    private ScanSubmissionRateLimiter limiter(Clock clock, long windowSeconds, int max) {
        return new ScanSubmissionRateLimiter(windowSeconds, max, clock);
    }

    @Test
    void freshActorPermitted() {
        ScanSubmissionRateLimiter rl = limiter(fixed(BASE), 3600, 20);
        assertTrue(rl.tryAcquire("alice"));
    }

    @Test
    void exactlyTwentyAllowed_twentyFirstDenied() {
        ScanSubmissionRateLimiter rl = limiter(fixed(BASE), 3600, 20);
        for (int i = 0; i < 20; i++) {
            assertTrue(rl.tryAcquire("bob"), "submission #" + (i + 1) + " must be allowed");
            rl.recordSubmission("bob");
        }
        assertFalse(rl.tryAcquire("bob"), "21st submission must be denied");
    }

    @Test
    void retryAfterIsClampedToOneAtWindowBoundary() {
        Clock[] clocks = {fixed(BASE)};
        Clock proxy = new Clock() {
            @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
            @Override public Clock withZone(java.time.ZoneId zone) { return clocks[0].withZone(zone); }
            @Override public Instant instant() { return clocks[0].instant(); }
        };
        ScanSubmissionRateLimiter rl = limiter(proxy, 3600, 2);
        rl.recordSubmission("carol");
        rl.recordSubmission("carol");
        assertEquals(3600L, rl.retryAfterSeconds("carol"));

        clocks[0] = Clock.offset(fixed(BASE), Duration.ofSeconds(3600));
        assertEquals(1L, rl.retryAfterSeconds("carol"));
    }

    @Test
    void differentActorsTrackedIndependently() {
        ScanSubmissionRateLimiter rl = limiter(fixed(BASE), 3600, 2);
        rl.recordSubmission("dave");
        rl.recordSubmission("dave");
        assertFalse(rl.tryAcquire("dave"));
        assertTrue(rl.tryAcquire("erin"), "actor erin must not inherit dave's budget");
    }

    @Test
    void slidingWindow_oldEntriesPrunedAfterWindowElapses() {
        Clock[] clocks = {fixed(BASE)};
        Clock proxy = new Clock() {
            @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
            @Override public Clock withZone(java.time.ZoneId zone) { return clocks[0].withZone(zone); }
            @Override public Instant instant() { return clocks[0].instant(); }
        };
        ScanSubmissionRateLimiter rl = limiter(proxy, 3600, 2);
        rl.recordSubmission("frank");
        rl.recordSubmission("frank");
        assertFalse(rl.tryAcquire("frank"), "denied at budget");

        clocks[0] = Clock.offset(fixed(BASE), Duration.ofSeconds(3601));
        assertTrue(rl.tryAcquire("frank"), "post-window: pruned entries free up budget");
    }
}
