package io.castellum.security;

import java.time.Instant;
import java.util.List;

public record LoginResponse(String token, Instant expiresAt, List<String> roles) {}
