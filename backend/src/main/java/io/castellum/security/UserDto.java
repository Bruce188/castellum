package io.castellum.security;

import java.time.Instant;

/**
 * Read-only projection of {@link User} returned by the user-management API.
 * Intentionally omits {@code passwordHash} — the hash MUST NOT leave the server
 * even in admin responses.
 */
public record UserDto(
        Long id,
        String username,
        Role role,
        boolean enabled,
        Instant createdAt,
        Instant lastLoginAt) {

    public static UserDto from(User u) {
        return new UserDto(
                u.getId(),
                u.getUsername(),
                u.getRole(),
                u.isEnabled(),
                u.getCreatedAt(),
                u.getLastLoginAt());
    }
}
