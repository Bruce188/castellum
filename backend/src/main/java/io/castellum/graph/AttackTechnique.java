package io.castellum.graph;

/**
 * MITRE ATT&CK technique identifier and human-readable name.
 *
 * <p>Used statically by {@link AttackTechniqueMapper} — there is no per-instance variation in v1.
 */
public record AttackTechnique(String id, String name) {

    public AttackTechnique {
        if (id == null || id.isBlank()) throw new IllegalArgumentException("id must not be blank");
        if (name == null || name.isBlank()) throw new IllegalArgumentException("name must not be blank");
    }
}
