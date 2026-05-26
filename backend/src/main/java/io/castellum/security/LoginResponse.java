package io.castellum.security;

import java.time.Instant;
import java.util.List;

/**
 * Payload returned by {@code POST /api/auth/login}.
 *
 * <p>{@code mustChangePassword} is set to {@code true} when the authenticated
 * user has {@code lastLoginAt == null} <em>and</em> their username matches a
 * bootstrap principal (admin/viewer seeded from env). The frontend uses this
 * flag to mount the full-screen rotation overlay before any other route loads.
 * Existing call sites that still construct {@code LoginResponse} with the
 * 3-arg form get {@code mustChangePassword = false} via the compact ctor.
 */
public record LoginResponse(String token, Instant expiresAt, List<String> roles, boolean mustChangePassword) {
    public LoginResponse(String token, Instant expiresAt, List<String> roles) {
        this(token, expiresAt, roles, false);
    }
}
