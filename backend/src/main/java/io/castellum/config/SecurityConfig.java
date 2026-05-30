package io.castellum.config;

import io.castellum.security.JwtAuthenticationFilter;
import io.castellum.security.RbacAccessDeniedHandler;
import io.castellum.security.RbacAuthenticationEntryPoint;
import io.castellum.security.RemoteAgentTokenAuthFilter;
import io.castellum.security.RemoteAgentTokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
import org.springframework.security.web.util.matcher.AnyRequestMatcher;

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

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration cfg) throws Exception {
        return cfg.getAuthenticationManager();
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
                .contentSecurityPolicy(c -> c.policyDirectives("default-src 'self'"))
                .httpStrictTransportSecurity(s -> s
                    .requestMatcher(AnyRequestMatcher.INSTANCE)
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
