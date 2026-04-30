package io.castellum.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class LoginRateLimiter {

    private final long windowSeconds;
    private final int maxAttempts;
    private final Clock clock;
    private final Map<String, Deque<Instant>> attempts = new ConcurrentHashMap<>();

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

    private void prune(String remoteAddr) {
        Deque<Instant> dq = attempts.get(remoteAddr);
        if (dq == null) return;
        Instant cutoff = clock.instant().minusSeconds(windowSeconds);
        while (!dq.isEmpty() && dq.peekFirst().isBefore(cutoff)) {
            dq.pollFirst();
        }
    }
}
