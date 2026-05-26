package io.castellum.security;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Body for {@code POST /api/auth/change-password}. The new password must be
 * at least 8 characters and is upper-bounded to keep BCrypt's 72-byte limit
 * from silently truncating long input. The old password is required so the
 * server can re-verify the caller's identity before accepting the change.
 */
public record ChangePasswordRequest(
        @NotBlank String oldPassword,
        @NotBlank @Size(min = 8, max = 256) String newPassword) {}
