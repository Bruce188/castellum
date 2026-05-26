package io.castellum.security;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Strategy interface for resolving the effective client IP address from an
 * incoming HTTP request.
 *
 * <p>Two built-in implementations are provided:
 * <ul>
 *   <li>{@link RemoteAddrProvider} — returns {@code request.getRemoteAddr()} directly.
 *       Use when Castellum is directly internet-facing with no reverse proxy.</li>
 *   <li>{@link XForwardedForProvider} — honours the {@code X-Forwarded-For} header
 *       when the direct caller is in a configured CIDR trust list.
 *       Use when Castellum sits behind a trusted reverse proxy.</li>
 * </ul>
 *
 * <p>The active implementation is selected by
 * {@code castellum.security.rate-limit.client-address-strategy} (values:
 * {@code remote-addr} | {@code xff}).
 */
public interface ClientAddressResolver {

    /**
     * Returns the effective client IP address for rate-limiting purposes.
     *
     * @param request the incoming HTTP request
     * @return a non-null IP address string
     */
    String resolve(HttpServletRequest request);
}
