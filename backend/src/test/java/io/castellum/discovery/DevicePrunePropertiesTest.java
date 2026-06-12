package io.castellum.discovery;

import io.castellum.audit.AuditService;
import io.castellum.domain.DeviceRepository;
import io.castellum.risk.RiskCacheEvictor;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.boot.convert.ApplicationConversionService;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Binds the REAL {@code castellum.discovery.public-device-prune.*} property keys through a
 * Spring context, closing the gap left by the unit tests (which construct the beans with
 * literal values and would stay green if a {@code @Value} key were typo'd or renamed —
 * the inline defaults {@code :true} / {@code :P14D} silently mask such drift).
 *
 * <p>The {@link ApplicationConversionService} initializer mirrors what
 * {@code SpringApplication} installs at boot. The TTL binds as a raw String and is parsed
 * strictly as ISO-8601 by the service constructor, so a bare {@code 14} — or any other
 * non-ISO value — must fail startup outright.
 */
class DevicePrunePropertiesTest {

    private static final Instant NOW = Instant.parse("2026-06-12T03:30:00Z");

    private final DeviceRepository deviceRepository = mock(DeviceRepository.class);
    private final AuditService auditService = mock(AuditService.class);
    private final RiskCacheEvictor riskCacheEvictor = mock(RiskCacheEvictor.class);

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
        .withInitializer(ctx -> ctx.getBeanFactory()
            .setConversionService(ApplicationConversionService.getSharedInstance()))
        .withBean(DeviceRepository.class, () -> deviceRepository)
        .withBean(AuditService.class, () -> auditService)
        .withBean(RiskCacheEvictor.class, () -> riskCacheEvictor)
        .withBean(Clock.class, () -> Clock.fixed(NOW, ZoneOffset.UTC))
        .withBean(DevicePruneService.class)
        .withBean(DevicePruneScheduler.class);

    @Test
    void noProperties_defaultsApply_enabledTrue_ttlP14D() {
        runner.run(context -> {
            when(deviceRepository.deleteStaleByScopeAndSources(eq(DiscoveryScope.PUBLIC), any(), any()))
                .thenReturn(0);

            // Default enabled=true — the tick must reach the service and hit the repository.
            context.getBean(DevicePruneScheduler.class).runScheduledPrune();

            ArgumentCaptor<Instant> cutoff = ArgumentCaptor.forClass(Instant.class);
            verify(deviceRepository).deleteStaleByScopeAndSources(
                eq(DiscoveryScope.PUBLIC), cutoff.capture(), eq(DevicePruneService.PRUNABLE_SOURCES));
            assertThat(cutoff.getValue())
                .as("default TTL must bind as P14D")
                .isEqualTo(NOW.minus(Duration.ofDays(14)));
        });
    }

    @Test
    void boundProperties_disabledSkipsService_andTtlP30DBinds() {
        runner.withPropertyValues(
                "castellum.discovery.public-device-prune.enabled=false",
                "castellum.discovery.public-device-prune.ttl=P30D")
            .run(context -> {
                // Kill switch bound from the REAL key: the tick must not touch the service.
                context.getBean(DevicePruneScheduler.class).runScheduledPrune();
                verifyNoInteractions(deviceRepository);

                // The TTL bound from the REAL key: invoking the service directly proves P30D.
                when(deviceRepository.deleteStaleByScopeAndSources(eq(DiscoveryScope.PUBLIC), any(), any()))
                    .thenReturn(0);
                context.getBean(DevicePruneService.class).pruneStalePublicDevices();

                ArgumentCaptor<Instant> cutoff = ArgumentCaptor.forClass(Instant.class);
                verify(deviceRepository).deleteStaleByScopeAndSources(
                    eq(DiscoveryScope.PUBLIC), cutoff.capture(), eq(DevicePruneService.PRUNABLE_SOURCES));
                assertThat(cutoff.getValue())
                    .as("ttl property must bind as ISO-8601 P30D")
                    .isEqualTo(NOW.minus(Duration.ofDays(30)));
            });
    }

    @Test
    void bareNumberTtl_failsStartupViaStrictIsoParse() {
        runner.withPropertyValues("castellum.discovery.public-device-prune.ttl=14")
            .run(context -> {
                assertThat(context).hasFailed();
                // The constructor's IllegalArgumentException wraps the DateTimeParseException,
                // so walk the chain for the service's own exception rather than the root cause.
                Throwable failure = context.getStartupFailure();
                while (failure != null
                        && !(failure instanceof IllegalArgumentException
                             && failure.getMessage() != null
                             && failure.getMessage().contains(
                                 "castellum.discovery.public-device-prune.ttl"))) {
                    failure = failure.getCause();
                }
                assertThat(failure)
                    .as("a bare '14' is not ISO-8601 and must be rejected by the strict parse at boot")
                    .isNotNull()
                    .hasMessageContaining("DISCOVERY_PUBLIC_DEVICE_TTL")
                    .hasMessageContaining("14")
                    .hasMessageContaining("ISO-8601");
            });
    }
}
