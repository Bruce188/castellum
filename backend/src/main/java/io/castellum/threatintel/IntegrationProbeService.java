package io.castellum.threatintel;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.http.client.ClientHttpRequestFactoryBuilder;
import org.springframework.boot.http.client.ClientHttpRequestFactorySettings;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;

import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.time.Duration;

/**
 * Bounded-timeout reachability probe for TAXII 2.1 and MISP integrations.
 *
 * <p>Any HTTP response (including 401/403 from an auth-gated server) is treated as
 * {@code reachable=true}. Connection refused / host-unreachable throws
 * {@link IntegrationProbeUnreachableException}; timeouts throw
 * {@link IntegrationProbeTimeoutException}.
 */
@Service
public class IntegrationProbeService {

    private static final MediaType TAXII_21 =
            MediaType.parseMediaType("application/taxii+json;version=2.1");

    private final RestClient client;

    public IntegrationProbeService(
            RestClient.Builder builder,
            @Value("${castellum.integration.probe.connect-timeout-ms:3000}") int connectTimeoutMs,
            @Value("${castellum.integration.probe.read-timeout-ms:5000}") int readTimeoutMs) {
        this(builder.requestFactory(buildTimeoutFactory(connectTimeoutMs, readTimeoutMs)).build());
    }

    /** Package-visible for testing — accepts an already-configured {@link RestClient}. */
    IntegrationProbeService(RestClient client) {
        this.client = client;
    }

    /**
     * Builds a {@link SimpleClientHttpRequestFactory} carrying the given connect and read
     * timeouts. Package-visible so it can be tested independently of the Spring context.
     */
    static SimpleClientHttpRequestFactory buildTimeoutFactory(int connectTimeoutMs, int readTimeoutMs) {
        ClientHttpRequestFactorySettings settings = ClientHttpRequestFactorySettings.defaults()
                .withConnectTimeout(Duration.ofMillis(connectTimeoutMs))
                .withReadTimeout(Duration.ofMillis(readTimeoutMs));
        return ClientHttpRequestFactoryBuilder.simple().build(settings);
    }

    /**
     * Probes the given integration endpoint for reachability.
     *
     * @param type         integration type — {@code "TAXII"} or {@code "MISP"} (case-insensitive)
     * @param url          base URL of the integration server
     * @param collectionId optional TAXII collection ID (currently unused by the probe)
     * @return {@link IntegrationProbeDto.ProbeResult} with {@code reachable=true} on any HTTP answer
     * @throws IntegrationProbeUnreachableException if the host is unreachable or connection is refused
     * @throws IntegrationProbeTimeoutException     if the request times out
     */
    public IntegrationProbeDto.ProbeResult probe(String type, String url, String collectionId) {
        String normalizedType = type == null ? "" : type.toUpperCase();
        String probeUrl = buildProbeUrl(normalizedType, url);

        try {
            if ("TAXII".equals(normalizedType)) {
                client.get()
                        .uri(probeUrl)
                        .header(HttpHeaders.ACCEPT, TAXII_21.toString())
                        .retrieve()
                        .toBodilessEntity();
            } else {
                client.get()
                        .uri(probeUrl)
                        .retrieve()
                        .toBodilessEntity();
            }
            return new IntegrationProbeDto.ProbeResult(true, "reachable");
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            // Any HTTP response — including 401/403 — means the server is up
            return new IntegrationProbeDto.ProbeResult(true,
                    "reachable (HTTP " + e.getStatusCode().value() + ")");
        } catch (ResourceAccessException e) {
            Throwable cause = e.getCause();
            if (cause instanceof SocketTimeoutException) {
                throw new IntegrationProbeTimeoutException("Probe timed out: " + e.getMessage(), e);
            }
            if (cause instanceof ConnectException || cause instanceof UnknownHostException) {
                throw new IntegrationProbeUnreachableException(
                        "Probe unreachable: " + e.getMessage(), e);
            }
            // Fallback: treat other I/O errors as unreachable
            throw new IntegrationProbeUnreachableException(
                    "Probe unreachable: " + e.getMessage(), e);
        }
    }

    // ---- Private helpers ----

    private static String buildProbeUrl(String normalizedType, String baseUrl) {
        String base = baseUrl == null ? "" : baseUrl.stripTrailing();
        // Remove trailing slash for consistent joining
        if (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        if ("TAXII".equals(normalizedType)) {
            return base + "/taxii2/";
        }
        // MISP: lightweight version endpoint
        return base + "/servers/getVersion";
    }
}
