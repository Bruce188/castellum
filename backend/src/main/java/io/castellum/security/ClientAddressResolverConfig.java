package io.castellum.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Selects and validates the active {@link ClientAddressResolver} bean based on
 * {@code castellum.security.rate-limit.client-address-strategy}.
 *
 * <p>Valid strategy values:
 * <ul>
 *   <li>{@code remote-addr} (default) — uses {@link RemoteAddrProvider}</li>
 *   <li>{@code xff} — uses {@link XForwardedForProvider} with the CIDR list from
 *       {@code castellum.security.rate-limit.trusted-proxies}</li>
 * </ul>
 *
 * <p>If strategy is {@code xff} and no trusted-proxies are configured, or if any
 * CIDR in the list is malformed, the application fails to start.
 */
@Configuration
public class ClientAddressResolverConfig {

    private static final Logger log = LoggerFactory.getLogger(ClientAddressResolverConfig.class);

    @Value("${castellum.security.rate-limit.client-address-strategy:remote-addr}")
    private String strategy;

    @Value("${castellum.security.rate-limit.trusted-proxies:}")
    private String trustedProxiesCsv;

    @Bean
    @Primary
    public ClientAddressResolver clientAddressResolver() {
        if ("xff".equalsIgnoreCase(strategy.trim())) {
            List<String> cidrs = parseCidrs(trustedProxiesCsv);
            if (cidrs.isEmpty()) {
                throw new IllegalStateException(
                        "client-address-strategy=xff requires at least one entry in " +
                        "castellum.security.rate-limit.trusted-proxies");
            }
            log.info("ClientAddressResolver: XFF mode with trusted CIDRs: {}", cidrs);
            // Construct and let the ctor validate each CIDR
            return new XForwardedForProvider(cidrs, null);
        }
        if (!"remote-addr".equalsIgnoreCase(strategy.trim())) {
            throw new IllegalStateException(
                    "Unknown client-address-strategy '" + strategy +
                    "'; valid values are: remote-addr, xff");
        }
        log.info("ClientAddressResolver: remote-addr mode");
        return new RemoteAddrProvider();
    }

    private static List<String> parseCidrs(String csv) {
        if (csv == null || csv.isBlank()) return List.of();
        return Arrays.stream(csv.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toList());
    }
}
