package io.castellum.discovery;

import java.util.Map;

/**
 * Derives a network-service descriptor (display name, canonical product, version, CPE) from a
 * docker image reference (e.g. {@code postgres:16},
 * {@code public.ecr.aws/supabase/postgres:17.6.1.029}).
 *
 * <p>The running image's tag carries the real version, so mapping it to a CPE lets
 * {@link io.castellum.cve.CveMatcher} range-match genuine CVEs for the deployed software — no
 * fabrication, just the version already declared by the image.
 *
 * <p><b>Conservative by design.</b> A version-bearing CPE is produced ONLY when both hold:
 * <ol>
 *   <li>the image base name maps to a curated NVD {@code vendor:product}, AND</li>
 *   <li>the tag yields a concrete numeric version.</li>
 * </ol>
 * Otherwise no CPE is emitted. A version-agnostic ({@code *}) CPE would match every CVE ever
 * filed against the product, so we decline rather than over-report. Images whose base name is not
 * in the curated map are recorded as inventory only (display name + version, no CPE).
 */
public final class DockerImageCpe {

    private DockerImageCpe() {
        throw new UnsupportedOperationException("static utility");
    }

    /**
     * Curated docker-image base name (lowercased) → canonical NVD {@code vendor:product} slug.
     * Kept deliberately small and high-confidence; unknown images degrade to inventory-only.
     * Note vendor ≠ image name in several cases (nginx→f5, mysql→oracle).
     */
    private static final Map<String, String> PRODUCTS = Map.ofEntries(
        Map.entry("postgres", "postgresql:postgresql"),
        Map.entry("postgresql", "postgresql:postgresql"),
        Map.entry("mysql", "oracle:mysql"),
        Map.entry("mariadb", "mariadb:mariadb"),
        Map.entry("mongo", "mongodb:mongodb"),
        Map.entry("mongodb", "mongodb:mongodb"),
        Map.entry("redis", "redis:redis"),
        Map.entry("nginx", "f5:nginx"),
        Map.entry("httpd", "apache:http_server"),
        Map.entry("haproxy", "haproxy:haproxy"),
        Map.entry("traefik", "traefik:traefik"),
        Map.entry("rabbitmq", "vmware:rabbitmq"),
        Map.entry("memcached", "memcached:memcached"),
        Map.entry("elasticsearch", "elastic:elasticsearch"),
        Map.entry("influxdb", "influxdata:influxdb"),
        Map.entry("grafana", "grafana:grafana"),
        Map.entry("vault", "hashicorp:vault"),
        Map.entry("consul", "hashicorp:consul")
    );

    /** A parsed image reference: base name (no registry/namespace/tag) + raw tag. */
    public record ImageRef(String baseName, String tag) {}

    /**
     * A service descriptor derived from an image: the {@code displayName} (always set when the
     * image is parseable), the canonical NVD {@code product} (null when unmapped), the concrete
     * {@code version} (null when the tag has none), and the full {@code cpe} (null unless mapped
     * AND versioned).
     */
    public record DerivedService(String displayName, String product, String version, String cpe) {}

    /**
     * Split an image reference into base name + tag. Strips any {@code @sha256:…} digest, the
     * registry host (which may carry a {@code :port}), and the namespace path — keeping only the
     * final path segment's {@code name[:tag]}.
     */
    public static ImageRef parse(String image) {
        if (image == null || image.isBlank()) {
            return new ImageRef(null, null);
        }
        String ref = image.trim();
        int at = ref.indexOf('@');
        if (at >= 0) {
            ref = ref.substring(0, at); // drop digest
        }
        int slash = ref.lastIndexOf('/');
        String last = slash >= 0 ? ref.substring(slash + 1) : ref; // drop registry + namespace
        int colon = last.indexOf(':');
        String name = colon >= 0 ? last.substring(0, colon) : last;
        String tag = colon >= 0 ? last.substring(colon + 1) : null;
        if (name.isBlank()) {
            return new ImageRef(null, null);
        }
        return new ImageRef(name.toLowerCase(), (tag != null && tag.isBlank()) ? null : tag);
    }

    /**
     * Concrete numeric version from a tag, or {@code null}. Strips a leading {@code v} and keeps
     * the leading dotted-numeric run: {@code "17.6.1.029"→"17.6.1.029"}, {@code "16"→"16"},
     * {@code "v1.22.3"→"1.22.3"}, {@code "1.25-alpine"→"1.25"}. Non-numeric tags
     * ({@code "latest"}, {@code "alpine"}, {@code "db"}) yield {@code null}.
     */
    public static String version(String tag) {
        if (tag == null || tag.isBlank()) {
            return null;
        }
        String t = tag.trim();
        if (t.length() > 1 && t.charAt(0) == 'v' && Character.isDigit(t.charAt(1))) {
            t = t.substring(1);
        }
        int i = 0;
        while (i < t.length() && (Character.isDigit(t.charAt(i)) || t.charAt(i) == '.')) {
            i++;
        }
        String num = t.substring(0, i);
        while (num.endsWith(".")) {
            num = num.substring(0, num.length() - 1);
        }
        if (num.isEmpty() || !Character.isDigit(num.charAt(0))) {
            return null;
        }
        return num;
    }

    /**
     * Derive the service descriptor for {@code image}, or {@code null} when the image is
     * null/blank/unparseable (the caller then records no service row).
     */
    public static DerivedService derive(String image) {
        ImageRef ref = parse(image);
        if (ref.baseName() == null) {
            return null;
        }
        String version = version(ref.tag());
        String vendorProduct = PRODUCTS.get(ref.baseName());
        if (vendorProduct != null) {
            String product = vendorProduct.substring(vendorProduct.indexOf(':') + 1);
            String cpe = (version != null)
                ? "cpe:2.3:a:" + vendorProduct + ":" + version + ":*:*:*:*:*:*:*"
                : null;
            return new DerivedService(product, product, version, cpe);
        }
        // Unmapped image — inventory only (raw base name, no CPE).
        return new DerivedService(ref.baseName(), null, version, null);
    }
}
