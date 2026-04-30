package io.castellum.config;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.net.URI;
import java.util.Arrays;
import java.util.List;

@Configuration
public class CorsConfig {

    @Bean
    public InitializingBean corsOriginValidator(
            @Value("${castellum.cors.allowed-origins:http://localhost:5173}") String allowedOrigins) {
        return () -> validateOrigins(allowedOrigins);
    }

    static void validateOrigins(String csv) {
        if (csv == null || csv.isBlank()) {
            throw new IllegalStateException("castellum.cors.allowed-origins must be set");
        }
        for (String raw : csv.split(",")) {
            String origin = raw.trim();
            if (origin.isEmpty()) {
                throw new IllegalStateException("CORS origin must be non-blank");
            }
            if (origin.equals("*")) {
                throw new IllegalStateException("CORS bare wildcard '*' forbidden — list specific origins");
            }
            if (origin.contains("*")) {
                throw new IllegalStateException("CORS wildcard subdomain forbidden: " + origin);
            }
            URI uri;
            try {
                uri = URI.create(origin);
            } catch (IllegalArgumentException e) {
                throw new IllegalStateException("Malformed CORS origin: " + origin, e);
            }
            String scheme = uri.getScheme();
            if (scheme == null || (!scheme.equals("http") && !scheme.equals("https"))) {
                throw new IllegalStateException("CORS origin must use http:// or https://: " + origin);
            }
            String host = uri.getHost();
            if (host == null) {
                throw new IllegalStateException("CORS origin must have a host: " + origin);
            }
            if (scheme.equals("http") && !isLocalhostHost(host)) {
                throw new IllegalStateException(
                    "CORS http:// only allowed for localhost; " + origin + " requires https://");
            }
        }
    }

    private static boolean isLocalhostHost(String host) {
        return host.equals("localhost") || host.equals("127.0.0.1")
            || host.equals("[::1]") || host.equals("::1");
    }

    @Bean
    public WebMvcConfigurer corsConfigurer(
        @Value("${castellum.cors.allowed-origins:http://localhost:5173}") String allowedOrigins) {
        String[] origins = allowedOrigins.split(",");
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/api/**")
                    .allowedOrigins(origins)
                    .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                    .allowedHeaders("Content-Type")
                    .allowCredentials(false)
                    .maxAge(3600);
            }
        };
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource(
        @Value("${castellum.cors.allowed-origins:http://localhost:5173}") String allowedOrigins) {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(Arrays.asList(allowedOrigins.split(",")));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("Content-Type", "Authorization"));
        config.setAllowCredentials(false);
        config.setMaxAge(3600L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", config);
        return source;
    }
}
