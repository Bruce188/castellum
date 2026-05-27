package io.castellum.risk;

import io.castellum.admin.InitialSyncService;
import io.castellum.cve.NvdSyncService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;

import static org.mockito.Mockito.*;

@SpringBootTest
@TestPropertySource(properties = "castellum.risk.refresh-cron=-")
class RiskFeedSchedulerTest {

    @Autowired RiskFeedScheduler scheduler;
    @MockBean EpssIngestionService epss;
    @MockBean KevIngestionService kev;
    @MockBean NvdSyncService nvd;
    @MockBean InitialSyncService initialSyncService;

    @Test
    void runFeeds_invokesEpssThenKev() throws Exception {
        scheduler.runFeeds();
        var inOrder = inOrder(epss, kev);
        inOrder.verify(epss).ingest();
        inOrder.verify(kev).ingest();
    }

    @Test
    void runFeeds_kevStillRunsWhenEpssThrows() throws Exception {
        when(epss.ingest()).thenThrow(new IOException("boom"));
        scheduler.runFeeds();
        verify(kev).ingest();
    }

    @Test
    void runFeeds_doesNotPropagateKevFailure() throws Exception {
        when(kev.ingest()).thenThrow(new IOException("boom"));
        scheduler.runFeeds();
        verify(epss).ingest();
    }

    @Test
    void runFeeds_invokesNvdIncrementalPullAfterKev() throws Exception {
        when(initialSyncService.isInFlight()).thenReturn(false);
        scheduler.runFeeds();
        var inOrder = inOrder(epss, kev, nvd);
        inOrder.verify(epss).ingest();
        inOrder.verify(kev).ingest();
        inOrder.verify(nvd).incrementalPull();
    }

    @Test
    void runFeeds_skipsNvdWhenManualSyncInFlight() throws Exception {
        when(initialSyncService.isInFlight()).thenReturn(true);
        scheduler.runFeeds();
        verify(nvd, never()).incrementalPull();
        verify(epss).ingest();
        verify(kev).ingest();
    }

    @Test
    void runFeeds_nvdFailureDoesNotPropagate_norAbortEpssKev() throws Exception {
        when(initialSyncService.isInFlight()).thenReturn(false);
        when(nvd.incrementalPull()).thenThrow(new IOException("nvd boom"));
        scheduler.runFeeds();
        verify(epss).ingest();
        verify(kev).ingest();
    }
}
