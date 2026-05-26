package io.castellum.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class LoginRateLimiter {

    private final long windowSeconds;
    private final int maxAttempts;
    private final Clock clock;

    /**
     * Outer map of IP → sliding-window failure timestamps.
     * <p>Exposed package-private for test assertions via {@link #attempts()}.
     */
    final Map<String, Deque<Instant>> attempts = new ConcurrentHashMap<>();

    public LoginRateLimiter(
            @Value("${castellum.security.rate-limit.login-window-seconds:60}") long windowSeconds,
            @Value("${castellum.security.rate-limit.login-max-attempts:10}") int maxAttempts,
            Clock clock) {
        this.windowSeconds = windowSeconds;
        this.maxAttempts = maxAttempts;
        this.clock = clock;
    }

    /** Returns true if this attempt is permitted; false if it would exceed the budget. */
    public synchronized boolean tryAcquire(String remoteAddr) {
        prune(remoteAddr);
        Deque<Instant> dq = attempts.computeIfAbsent(remoteAddr, k -> new ArrayDeque<>());
        return dq.size() < maxAttempts;
    }

    /** Record a failed attempt against the budget. Call on auth failure paths only. */
    public synchronized void recordFailure(String remoteAddr) {
        prune(remoteAddr);
        attempts.computeIfAbsent(remoteAddr, k -> new ArrayDeque<>()).addLast(clock.instant());
    }

    public synchronized long retryAfterSeconds(String remoteAddr) {
        prune(remoteAddr);
        Deque<Instant> dq = attempts.get(remoteAddr);
        if (dq == null || dq.isEmpty()) return 0L;
        Instant oldest = dq.peekFirst();
        long remaining = windowSeconds - Duration.between(oldest, clock.instant()).getSeconds();
        return Math.max(remaining, 1L);
    }

    /**
     * Scheduled sweep that prunes every tracked IP and removes those whose deque
     * becomes empty, preventing unbounded outer-map growth.
     * <p>Interval is driven by
     * {@code castellum.security.rate-limit.eviction-interval-millis} (default 60 000 ms).
     */
    @Scheduled(fixedDelayString =
            "${castellum.security.rate-limit.eviction-interval-millis:60000}")
    public synchronized void evictStaleEntries() {
        Iterator<Map.Entry<String, Deque<Instant>>> it = attempts.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, Deque<Instant>> entry = it.next();
            prune(entry.getKey());
            if (entry.getValue().isEmpty()) {
                it.remove();
            }
        }
    }

    /**
     * Package-private view of the attempts map for white-box tests.
     * Do not call from production code.
     */
    Map<String, Deque<Instant>> attempts() {
        return attempts;
    }

    private void prune(String remoteAddr) {
        Deque<Instant> dq = attempts.get(remoteAddr);
        if (dq == null) return;
        Instant cutoff = clock.instant().minusSeconds(windowSeconds);
        while (!dq.isEmpty() && dq.peekFirst().isBefore(cutoff)) {
            dq.pollFirst();
        }
    }
}
