package io.castellum.cve;

/**
 * Lightweight interface projection for STIX bundle assembly.
 * Selects only {@code cveId} and {@code description}, leaving the heavy
 * {@code raw_json} column out of the result set to bound heap usage.
 */
public interface CveStixView {
    String getCveId();
    String getDescription();
}
