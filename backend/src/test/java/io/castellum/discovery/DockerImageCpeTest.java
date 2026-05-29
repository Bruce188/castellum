package io.castellum.discovery;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** Unit tests for {@link DockerImageCpe} — image-ref parsing, version normalization, derivation. */
class DockerImageCpeTest {

    @Test
    void parse_simpleNameTag() {
        DockerImageCpe.ImageRef r = DockerImageCpe.parse("postgres:16");
        assertThat(r.baseName()).isEqualTo("postgres");
        assertThat(r.tag()).isEqualTo("16");
    }

    @Test
    void parse_registryNamespaceTag_dropsRegistryAndNamespace() {
        DockerImageCpe.ImageRef r = DockerImageCpe.parse("public.ecr.aws/supabase/postgres:17.6.1.029");
        assertThat(r.baseName()).isEqualTo("postgres");
        assertThat(r.tag()).isEqualTo("17.6.1.029");
    }

    @Test
    void parse_registryWithPort_notMistakenForTag() {
        DockerImageCpe.ImageRef r = DockerImageCpe.parse("localhost:5000/redis:7.2");
        assertThat(r.baseName()).isEqualTo("redis");
        assertThat(r.tag()).isEqualTo("7.2");
    }

    @Test
    void parse_digestStripped() {
        DockerImageCpe.ImageRef r = DockerImageCpe.parse("postgres:16@sha256:abc123def456");
        assertThat(r.baseName()).isEqualTo("postgres");
        assertThat(r.tag()).isEqualTo("16");
    }

    @Test
    void parse_noTag() {
        DockerImageCpe.ImageRef r = DockerImageCpe.parse("redis");
        assertThat(r.baseName()).isEqualTo("redis");
        assertThat(r.tag()).isNull();
    }

    @Test
    void parse_blank_baseNameNull() {
        assertThat(DockerImageCpe.parse(null).baseName()).isNull();
        assertThat(DockerImageCpe.parse("").baseName()).isNull();
        assertThat(DockerImageCpe.parse("   ").baseName()).isNull();
    }

    @Test
    void version_variants() {
        assertThat(DockerImageCpe.version("16")).isEqualTo("16");
        assertThat(DockerImageCpe.version("17.6.1.029")).isEqualTo("17.6.1.029");
        assertThat(DockerImageCpe.version("v1.22.3")).isEqualTo("1.22.3");
        assertThat(DockerImageCpe.version("1.25-alpine")).isEqualTo("1.25");
        assertThat(DockerImageCpe.version("latest")).isNull();
        assertThat(DockerImageCpe.version("alpine")).isNull();
        assertThat(DockerImageCpe.version("db")).isNull();
        assertThat(DockerImageCpe.version(null)).isNull();
        assertThat(DockerImageCpe.version("")).isNull();
    }

    @Test
    void derive_knownProductWithVersion_buildsCpe() {
        DockerImageCpe.DerivedService d = DockerImageCpe.derive("postgres:16");
        assertThat(d.product()).isEqualTo("postgresql");
        assertThat(d.displayName()).isEqualTo("postgresql");
        assertThat(d.version()).isEqualTo("16");
        assertThat(d.cpe()).isEqualTo("cpe:2.3:a:postgresql:postgresql:16:*:*:*:*:*:*:*");
    }

    @Test
    void derive_nginxMapsToF5Vendor() {
        DockerImageCpe.DerivedService d = DockerImageCpe.derive("nginx:1.27.0");
        assertThat(d.cpe()).isEqualTo("cpe:2.3:a:f5:nginx:1.27.0:*:*:*:*:*:*:*");
        assertThat(d.product()).isEqualTo("nginx");
    }

    @Test
    void derive_namespacedPostgres_resolvesToPostgresql() {
        DockerImageCpe.DerivedService d = DockerImageCpe.derive("public.ecr.aws/supabase/postgres:15.1.0.147");
        assertThat(d.cpe()).isEqualTo("cpe:2.3:a:postgresql:postgresql:15.1.0.147:*:*:*:*:*:*:*");
    }

    @Test
    void derive_knownProductNoVersion_noCpe() {
        // version-agnostic CPE would over-match every product CVE — decline instead
        DockerImageCpe.DerivedService d = DockerImageCpe.derive("redis:latest");
        assertThat(d.product()).isEqualTo("redis");
        assertThat(d.version()).isNull();
        assertThat(d.cpe()).isNull();
    }

    @Test
    void derive_unmappedImage_inventoryOnly() {
        DockerImageCpe.DerivedService d = DockerImageCpe.derive("kong:3.4.2");
        assertThat(d.displayName()).isEqualTo("kong");
        assertThat(d.product()).isNull();
        assertThat(d.version()).isEqualTo("3.4.2");
        assertThat(d.cpe()).isNull();
    }

    @Test
    void derive_blankImage_null() {
        assertThat(DockerImageCpe.derive(null)).isNull();
        assertThat(DockerImageCpe.derive("")).isNull();
    }

    // -----------------------------------------------------------------------
    // cpeForFingerprint — nmap product+version → CPE
    // -----------------------------------------------------------------------

    @Test
    void cpeForFingerprint_mysql_derivesCpe() {
        assertThat(DockerImageCpe.cpeForFingerprint("MySQL", "8.0.46-1.el9"))
            .isEqualTo("cpe:2.3:a:oracle:mysql:8.0.46:*:*:*:*:*:*:*");
    }

    @Test
    void cpeForFingerprint_caseInsensitive() {
        assertThat(DockerImageCpe.cpeForFingerprint("mysql", "8.0.46"))
            .isEqualTo("cpe:2.3:a:oracle:mysql:8.0.46:*:*:*:*:*:*:*");
        assertThat(DockerImageCpe.cpeForFingerprint("MYSQL", "8.0.46"))
            .isEqualTo("cpe:2.3:a:oracle:mysql:8.0.46:*:*:*:*:*:*:*");
    }

    @Test
    void cpeForFingerprint_unknownProduct_null() {
        assertThat(DockerImageCpe.cpeForFingerprint("SomeProprietaryDB", "3.1.4")).isNull();
    }

    @Test
    void cpeForFingerprint_noVersion_null() {
        assertThat(DockerImageCpe.cpeForFingerprint("MySQL", null)).isNull();
        assertThat(DockerImageCpe.cpeForFingerprint("MySQL", "")).isNull();
        assertThat(DockerImageCpe.cpeForFingerprint("MySQL", "some-non-numeric")).isNull();
    }

    @Test
    void cpeForFingerprint_nullProduct_null() {
        assertThat(DockerImageCpe.cpeForFingerprint(null, "8.0.46")).isNull();
    }

    @Test
    void cpeForFingerprint_compoundProductName_normalizesToFirstToken() {
        // nmap reports "PostgreSQL DB" — full string not in map; first token "postgresql" is
        assertThat(DockerImageCpe.cpeForFingerprint("PostgreSQL DB", "9.6.0"))
            .isEqualTo("cpe:2.3:a:postgresql:postgresql:9.6.0:*:*:*:*:*:*:*");
    }

    @Test
    void cpeForFingerprint_compoundNginxProductName_normalizesToFirstToken() {
        // "nginx HTTP server" → token "nginx" → f5:nginx
        assertThat(DockerImageCpe.cpeForFingerprint("nginx HTTP server", "1.25.0"))
            .isEqualTo("cpe:2.3:a:f5:nginx:1.25.0:*:*:*:*:*:*:*");
    }
}
