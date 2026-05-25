package io.castellum.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

/**
 * {@link ClientAddressResolver} that returns {@link HttpServletRequest#getRemoteAddr()}
 * verbatim. Use when Castellum is directly internet-facing with no trusted reverse proxy.
 *
 * <p>This is the default strategy when
 * {@code castellum.security.rate-limit.client-address-strategy} is {@code remote-addr}
 * or is absent.
 */
@Component("remoteAddrProvider")
public class RemoteAddrProvider implements ClientAddressResolver {

    @Override
    public String resolve(HttpServletRequest request) {
        return request.getRemoteAddr();
    }
}
