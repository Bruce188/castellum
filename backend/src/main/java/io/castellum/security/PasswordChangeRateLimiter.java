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

/**
 * Per-actor sliding-window rate limiter for the change-password endpoint.
 *
 * <p>Mirrors {@link LoginRateLimiter} structurally — separate bean so its
 * window/budget can be tuned independently from the login limiter and so the
 * two limiters do not share state. Keyed by the authenticated username (not
 * the source IP) because the threat model here is brute-forcing the
 * {@code oldPassword} of a specific account, not generic credential stuffing.
 */
@Component
public class PasswordChangeRateLimiter {

    private final long windowSeconds;
    private final int maxAttempts;
    private final Clock clock;

    final Map<String, Deque<Instant>> attempts = new ConcurrentHashMap<>();

    public PasswordChangeRateLimiter(
            @Value("${castellum.security.rate-limit.password-change-window-seconds:60}") long windowSeconds,
            @Value("${castellum.security.rate-limit.password-change-max-attempts:3}") int maxAttempts,
            Clock clock) {
        this.windowSeconds = windowSeconds;
        this.maxAttempts = maxAttempts;
        this.clock = clock;
    }

    /** Returns true if this attempt is permitted; false if it would exceed the budget. */
    public synchronized boolean tryAcquire(String actor) {
        prune(actor);
        Deque<Instant> dq = attempts.computeIfAbsent(actor, k -> new ArrayDeque<>());
        return dq.size() < maxAttempts;
    }

    /** Record any attempt against the budget — pass or fail counts equally. */
    public synchronized void recordAttempt(String actor) {
        prune(actor);
        attempts.computeIfAbsent(actor, k -> new ArrayDeque<>()).addLast(clock.instant());
    }

    public synchronized long retryAfterSeconds(String actor) {
        prune(actor);
        Deque<Instant> dq = attempts.get(actor);
        if (dq == null || dq.isEmpty()) return 0L;
        Instant oldest = dq.peekFirst();
        long remaining = windowSeconds - Duration.between(oldest, clock.instant()).getSeconds();
        return Math.max(remaining, 1L);
    }

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

    Map<String, Deque<Instant>> attempts() {
        return attempts;
    }

    private void prune(String actor) {
        Deque<Instant> dq = attempts.get(actor);
        if (dq == null) return;
        Instant cutoff = clock.instant().minusSeconds(windowSeconds);
        while (!dq.isEmpty() && dq.peekFirst().isBefore(cutoff)) {
            dq.pollFirst();
        }
    }
}
