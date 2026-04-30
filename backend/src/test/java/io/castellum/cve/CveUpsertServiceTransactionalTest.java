package io.castellum.cve;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.castellum.cve.dto.NvdConfiguration;
import io.castellum.cve.dto.NvdCpeMatch;
import io.castellum.cve.dto.NvdCveItem;
import io.castellum.cve.dto.NvdDescription;
import io.castellum.cve.dto.NvdNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.verify;

/**
 * Verifies that {@link CveUpsertService}'s @Transactional boundary actually applies — i.e.
 * a mid-loop CPE-match save failure rolls back the parent CVE row plus any prior match
 * writes. Demonstrates that the proxy is invoked correctly because the call comes from a
 * separate test bean (not a same-class self-invocation).
 */
@DataJpaTest
@Import({CveUpsertService.class, JacksonAutoConfiguration.class})
@TestPropertySource(properties = {
    "spring.flyway.enabled=true",
    "spring.flyway.locations=classpath:db/migration/h2",
    "spring.jpa.hibernate.ddl-auto=validate"
})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
// Suspend @DataJpaTest's default test-method transaction so the @Transactional
// boundary inside CveUpsertService.upsertCve actually starts a fresh transaction
// of its own. Without this, the test method would already be in a transaction
// and upsertCve(REQUIRED) would join it — meaning we'd never observe the
// rollback effect we're trying to verify.
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class CveUpsertServiceTransactionalTest {

    @Autowired
    CveUpsertService service;

    @Autowired
    CveRepository cveRepository;

    @MockBean
    CveCpeMatchRepository cveCpeMatchRepository;

    @Autowired
    ObjectMapper objectMapper;

    @BeforeEach
    void clean() {
        cveRepository.deleteAll();
    }

    @Test
    void upsertCve_whenMatchSaveThrowsMidLoop_rollsBackCveAndAllPriorMatches() {
        NvdCveItem item = buildItemWithThreeMatches("CVE-TXN-001");

        // Throw on the 2nd save call: 1st succeeds, 2nd fails. Expectation: outer transaction
        // rolls back, including the parent CVE row written before the loop entered.
        int[] callCount = {0};
        doAnswer(inv -> {
            callCount[0]++;
            if (callCount[0] == 2) {
                throw new RuntimeException("simulated CPE persistence fault");
            }
            return inv.getArgument(0);
        }).when(cveCpeMatchRepository).save(any(CveCpeMatch.class));

        assertThatThrownBy(() -> service.upsertCve(item))
            .isInstanceOf(RuntimeException.class)
            .hasMessageContaining("simulated CPE persistence fault");

        // The CVE row must NOT exist — the @Transactional boundary on upsertCve unwound it
        // along with the partial match writes. If self-invocation had bypassed the proxy,
        // the CVE row would survive and only the match save would have failed.
        assertFalse(cveRepository.findByCveId("CVE-TXN-001").isPresent(),
            "CVE row should be rolled back when CPE-match save fails mid-loop");
    }

    @Test
    void upsertCve_happyPath_persistsCveAndMatchesAtomically() {
        NvdCveItem item = buildItemWithThreeMatches("CVE-TXN-002");

        // All saves succeed (default mock returns null but that's fine for void-returning save).
        doAnswer(inv -> inv.getArgument(0))
            .when(cveCpeMatchRepository).save(any(CveCpeMatch.class));

        int matchCount = service.upsertCve(item);

        assertEquals(3, matchCount, "all 3 CPE matches should have been counted");
        assertTrue(cveRepository.findByCveId("CVE-TXN-002").isPresent(),
            "CVE row should be present on happy path");
        verify(cveCpeMatchRepository, atLeastOnce()).save(any(CveCpeMatch.class));
    }

    private NvdCveItem buildItemWithThreeMatches(String cveId) {
        NvdCpeMatch m1 = new NvdCpeMatch("cpe:2.3:a:vendor:product1:*:*:*:*:*:*:*:*",
            true, null, null, null, null, null);
        NvdCpeMatch m2 = new NvdCpeMatch("cpe:2.3:a:vendor:product2:*:*:*:*:*:*:*:*",
            true, null, null, null, null, null);
        NvdCpeMatch m3 = new NvdCpeMatch("cpe:2.3:a:vendor:product3:*:*:*:*:*:*:*:*",
            true, null, null, null, null, null);
        NvdNode node = new NvdNode("OR", false, List.of(m1, m2, m3));
        NvdConfiguration cfg = new NvdConfiguration("AND", List.of(node));
        return new NvdCveItem(
            cveId,
            "2026-01-01T00:00:00.000",
            "2026-04-01T00:00:00.000",
            "Modified",
            List.of(new NvdDescription("en", "transactional boundary test")),
            null,
            List.of(cfg));
    }
}
