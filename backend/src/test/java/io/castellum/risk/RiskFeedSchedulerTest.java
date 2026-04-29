package io.castellum.risk;

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
}
