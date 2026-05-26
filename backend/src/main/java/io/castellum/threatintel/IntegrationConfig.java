package io.castellum.threatintel;

import jakarta.persistence.*;

import java.time.Instant;

/**
 * Persisted TAXII / MISP integration configuration. One row per
 * {@link #integrationType}. Secrets live in {@link #encryptedCredentials}
 * (AES-256-GCM, see {@link io.castellum.security.AesGcmCipher}); non-secret
 * fields live in {@link #configJson} (free-form JSON managed by the controller).
 */
@Entity
@Table(name = "integration_config")
public class IntegrationConfig {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "integration_type", nullable = false, unique = true)
    private String integrationType;

    @Column(name = "config_json", nullable = false, columnDefinition = "TEXT")
    private String configJson;

    @Column(name = "encrypted_credentials", nullable = false)
    private byte[] encryptedCredentials;

    @Column(name = "last_push_at")
    private Instant lastPushAt;

    @Column(name = "last_push_status")
    private String lastPushStatus;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    public IntegrationConfig() {}

    public IntegrationConfig(String integrationType, String configJson, byte[] encryptedCredentials) {
        this.integrationType = integrationType;
        this.configJson = configJson;
        this.encryptedCredentials = encryptedCredentials;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getIntegrationType() { return integrationType; }
    public void setIntegrationType(String integrationType) { this.integrationType = integrationType; }

    public String getConfigJson() { return configJson; }
    public void setConfigJson(String configJson) { this.configJson = configJson; }

    public byte[] getEncryptedCredentials() { return encryptedCredentials; }
    public void setEncryptedCredentials(byte[] encryptedCredentials) { this.encryptedCredentials = encryptedCredentials; }

    public Instant getLastPushAt() { return lastPushAt; }
    public void setLastPushAt(Instant lastPushAt) { this.lastPushAt = lastPushAt; }

    public String getLastPushStatus() { return lastPushStatus; }
    public void setLastPushStatus(String lastPushStatus) { this.lastPushStatus = lastPushStatus; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }

    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }
}
