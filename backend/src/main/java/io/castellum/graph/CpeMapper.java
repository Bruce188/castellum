package io.castellum.graph;

import io.castellum.domain.NetworkService;

/**
 * Lossy, deterministic CPE 2.3 string derivation from a {@link NetworkService}.
 *
 * <p>v1 mapping: vendor=product=lowercase-sanitized(name). This is deliberately approximate;
 * for example, canonical CPEs for OpenSSH use vendor=openbsd, whereas this mapper produces
 * vendor=openssh. Acceptance-test fixtures must seed a {@code cve_cpe_match} row keyed on
 * the mapped form. A curated {@code (name → vendor, product)} table is deferred per analysis-v5 OQ#2.
 *
 * <p>Sanitization: keep {@code [a-z0-9_-]} only. Returns {@code null} when the sanitized slug
 * is empty. Null/blank version maps to {@code *}.
 */
public final class CpeMapper {

    private CpeMapper() {
        throw new UnsupportedOperationException("static utility");
    }

    /**
     * Derive a CPE 2.3 string from a {@link NetworkService}.
     *
     * @return CPE string, or {@code null} if the service name is null/blank or sanitizes to empty.
     */
    public static String toCpe23(NetworkService service) {
        if (service == null || service.getName() == null) return null;
        String slug = service.getName().toLowerCase().replaceAll("[^a-z0-9_-]", "");
        if (slug.isEmpty()) return null;
        String version = (service.getVersion() == null || service.getVersion().isBlank())
                ? "*" : service.getVersion();
        return "cpe:2.3:a:" + slug + ":" + slug + ":" + version + ":*:*:*:*:*:*:*";
    }
}
