package io.castellum.config;

import io.castellum.security.JwtAuthenticationFilter;
import io.castellum.security.RbacAccessDeniedHandler;
import io.castellum.security.RbacAuthenticationEntryPoint;
import io.castellum.security.RemoteAgentTokenAuthFilter;
import io.castellum.security.RemoteAgentTokenRepository;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    /**
     * Optional: injected when the JPA layer is present (full SpringBootTest / production).
     * Null in {@code @WebMvcTest} slices that don't load JPA repositories.
     */
    @Autowired(required = false)
    @Nullable
    private RemoteAgentTokenRepository remoteAgentTokenRepository;

    /** Lowered only by the test config: at cost 12 every login burns ~250ms of CPU. */
    @Value("${castellum.security.bcrypt-strength:12}")
    private int bcryptStrength = 12;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(bcryptStrength);
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration cfg) throws Exception {
        return cfg.getAuthenticationManager();
    }

    /**
     * Fail-fast CORS guard for production. Local dev serves the SPA from the Vite origin
     * (http://localhost:5173) and relies on the CORS allow-list; production serves the SPA
     * same-origin, so CORS is moot and the localhost dev allow-list must never ship. When the
     * {@code prod}/{@code production} profile is active, refuse to start unless
     * CORS_ALLOWED_ORIGINS has been set to a real (non-loopback) origin — rather than silently
     * shipping the dev default. Local dev (no prod profile) is unaffected.
     */
    @Bean
    public InitializingBean corsProdOriginGuard(
            Environment env,
            @Value("${castellum.cors.allowed-origins:http://localhost:5173}") String allowedOrigins) {
        return () -> {
            boolean prod = false;
            for (String profile : env.getActiveProfiles()) {
                if (profile.equalsIgnoreCase("prod") || profile.equalsIgnoreCase("production")) {
                    prod = true;
                    break;
                }
            }
            if (!prod) {
                return;
            }
            String value = allowedOrigins == null ? "" : allowedOrigins.trim();
            boolean loopback = value.contains("localhost")
                    || value.contains("127.0.0.1")
                    || value.contains("::1");
            if (value.isEmpty() || loopback) {
                throw new IllegalStateException(
                    "CORS_ALLOWED_ORIGINS must be set to a production origin when the 'prod' "
                    + "profile is active; refusing to start with the localhost dev default "
                    + "(resolved value: '" + allowedOrigins + "'). Set CORS_ALLOWED_ORIGINS to "
                    + "your https operator origin.");
            }
        };
    }

    @Bean
    public SecurityFilterChain api(
            HttpSecurity http,
            JwtAuthenticationFilter jwt,
            RbacAccessDeniedHandler deny,
            RbacAuthenticationEntryPoint entry) throws Exception {
        http
            .cors(Customizer.withDefaults())
            .headers(h -> h
                // CSP calibrated for the same-origin Vite/React SPA: external hashed JS/CSS from
                // /assets ('self'), no inline <script> (script-src 'self' blocks injected inline
                // scripts), 'unsafe-inline' styles for libs that set element styles (e.g. cytoscape),
                // data: for favicon/fonts, and connect-src 'self' — the SPA calls only the same-origin
                // /api (no ws/wss, no cross-origin fetch), blocking JWT-in-localStorage exfil to
                // attacker origins.
                .contentSecurityPolicy(c -> c.policyDirectives(
                    "default-src 'self'; "
                    + "script-src 'self'; "
                    + "style-src 'self' 'unsafe-inline'; "
                    + "img-src 'self' data:; "
                    + "font-src 'self' data:; "
                    + "connect-src 'self'; "
                    + "frame-ancestors 'none'; "
                    + "base-uri 'self'; "
                    + "object-src 'none'"))
                // X-Content-Type-Options: nosniff (Spring default; reaffirmed so it survives any
                // future defaults-disabled change) + a Referrer-Policy that sends nothing on an
                // HTTPS→HTTP downgrade and only the origin cross-origin (outbound NVD/GitHub links).
                .contentTypeOptions(Customizer.withDefaults())
                .referrerPolicy(r -> r.policy(
                    ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
                // HSTS only on HTTPS-origin requests — never on plain HTTP. Sending HSTS over
                // cleartext is a no-op per RFC 6797 §7.2 and pins a stale https upgrade on
                // local-dev hosts (e.g. http://localhost). A TLS-terminating reverse proxy must
                // forward "X-Forwarded-Proto: https" for production HSTS to be emitted.
                .httpStrictTransportSecurity(s -> s
                    .requestMatcher(request ->
                        request.isSecure()
                            || "https".equalsIgnoreCase(request.getHeader("X-Forwarded-Proto")))
                    .includeSubDomains(true)
                    .maxAgeInSeconds(31536000))
                .frameOptions(f -> f.deny()))
            // CSRF disabled — stateless JWT API surface; no session, no cookie auth.
            .csrf(c -> c.disable())
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(a -> a
                .requestMatchers("/api/auth/login", "/actuator/health", "/error").permitAll()
                // /api/auth/change-password requires an authenticated principal — the
                // controller reads Authentication.getName() to identify the actor.
                .requestMatchers("/api/auth/change-password").authenticated()
                // Remote-agent push ingest: authenticated by bearer token (RemoteAgentTokenAuthFilter).
                .requestMatchers(HttpMethod.POST, "/api/discovery/remote-docker").hasRole("REMOTE_AGENT")
                // API + management stay authenticated (specific permits above win: login, health, error).
                .requestMatchers("/api/**", "/actuator/**").authenticated()
                // Same-origin SPA: the backend serves the React shell + static assets, and the
                // client-side routes (/cves, /topology, …) forward to index.html. These GETs are
                // public — the shell is not sensitive; all data stays behind the authenticated /api/**.
                .requestMatchers(HttpMethod.GET, "/**").permitAll()
                .anyRequest().authenticated())
            // Register jwt before UsernamePasswordAuthenticationFilter. The remote-agent
            // bearer filter below is also added before UsernamePasswordAuthenticationFilter
            // (registered after jwt), so the effective chain order is:
            // jwt → remoteAgentTokenAuthFilter → UsernamePasswordAuthenticationFilter.
            // For a remote-agent POST carrying an opaque bearer token, the jwt filter finds
            // no valid JWT and leaves the security context empty, then remoteAgentTokenAuthFilter
            // sets the ROLE_REMOTE_AGENT principal — verified end-to-end by RemoteDockerControllerTest.
            .addFilterBefore(jwt, UsernamePasswordAuthenticationFilter.class);

        // RemoteAgentTokenAuthFilter is created inline only when the JPA repository is
        // available. In @WebMvcTest slices (no JPA), the filter is skipped; the ingest route
        // is still gated by hasRole("REMOTE_AGENT") in the authorizeHttpRequests block above.
        if (remoteAgentTokenRepository != null) {
            RemoteAgentTokenAuthFilter remoteAgentTokenAuthFilter =
                    new RemoteAgentTokenAuthFilter(remoteAgentTokenRepository, passwordEncoder());
            http.addFilterBefore(remoteAgentTokenAuthFilter, UsernamePasswordAuthenticationFilter.class);
        }

        http.exceptionHandling(e -> e
                .authenticationEntryPoint(entry)
                .accessDeniedHandler(deny))
            .httpBasic(b -> b.disable())
            .formLogin(f -> f.disable());
        return http.build();
    }
}
