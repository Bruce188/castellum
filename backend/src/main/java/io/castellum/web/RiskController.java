package io.castellum.web;

import io.castellum.config.CacheNames;
import io.castellum.cve.Cve;
import io.castellum.cve.CveRepository;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.risk.CompositeScorer;
import io.castellum.risk.Criticality;
import io.castellum.risk.CvssExtractor;
import io.castellum.risk.DeviceRiskService;
import io.castellum.risk.DeviceRiskService.DeviceRiskResult;
import io.castellum.risk.EpssScoreRepository;
import io.castellum.risk.KevEntryRepository;
import io.castellum.risk.RiskInputs;
import io.castellum.risk.RiskScore;
import io.castellum.web.dto.DeviceRiskDto;
import io.castellum.web.dto.FeedsStatusDto;
import io.castellum.web.dto.TopRiskDeviceDto;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

@RestController
@RequestMapping("/api/risk")
public class RiskController {

    private static final int TOP_DEFAULT_N = 10;
    private static final int TOP_MAX_N = 100;

    /** Hard ceiling on the {@code ids} list accepted by the batch risk endpoint. */
    private static final int BATCH_MAX_IDS = 200;

    private final CveRepository cveRepo;
    private final DeviceRepository deviceRepo;
    private final EpssScoreRepository epssRepo;
    private final KevEntryRepository kevRepo;
    private final DeviceRiskService deviceRiskService;

    public RiskController(CveRepository cveRepo, DeviceRepository deviceRepo,
                           EpssScoreRepository epssRepo, KevEntryRepository kevRepo,
                           DeviceRiskService deviceRiskService) {
        this.cveRepo = cveRepo;
        this.deviceRepo = deviceRepo;
        this.epssRepo = epssRepo;
        this.kevRepo = kevRepo;
        this.deviceRiskService = deviceRiskService;
    }

    @GetMapping("/score")
    @PreAuthorize("hasAnyRole('VIEWER','ADMIN')")
    public RiskScore score(@RequestParam("cve") String cveId, @RequestParam("device") long deviceId) {
        Cve cve = cveRepo.findByCveId(cveId)
            .orElseThrow(() -> new NoSuchElementException("CVE not found: " + cveId));
        Device device = deviceRepo.findById(deviceId)
            .orElseThrow(() -> new NoSuchElementException("Device not found: " + deviceId));
        double cvssN = CvssExtractor.normalized(cve);
        double epss = epssRepo.findByCveId(cveId).map(e -> e.getEpss().doubleValue()).orElse(0.0);
        boolean kev = kevRepo.existsByCveId(cveId);
        var inputs = new RiskInputs(cvssN, epss, kev, device.getCriticality());
        return CompositeScorer.score(inputs);
    }

    /**
     * Feed-corpus status (NVD/EPSS/KEV row counts + freshness markers).
     *
     * <p>Backs {@code EmptyCorpusBanner}'s 10-second poll that flips the UI once a sync
     * populates the corpus. The six aggregate queries here (three {@code count()} full-table
     * scans + three {@code MAX(...)}) are the inherent cost — the NVD {@code count()} over a
     * ~270k-row table dominates and is recomputed on every poll. The result only changes when a
     * feed sync writes rows, so it is cached on {@link CacheNames#FEEDS_STATUS}.
     *
     * <p><b>Banner-correctness contract:</b> the cache TTL is deliberately short (≤ the poll
     * interval, see {@code CacheConfig.FEEDS_STATUS_TTL}) AND the cache is evicted on feed-sync
     * completion. Either alone keeps the banner correct within one poll cycle once feeds
     * populate; do not lengthen the TTL without preserving the evict-on-sync trigger.
     */
    @GetMapping("/feeds/status")
    @PreAuthorize("hasAnyRole('VIEWER','ADMIN')")
    @Cacheable(cacheNames = CacheNames.FEEDS_STATUS, key = "'singleton'")
    public FeedsStatusDto feedsStatus() {
        long epssCount = epssRepo.count();
        var epssMaxDate = epssRepo.findMaxScoreDate().orElse(null);
        long kevCount = kevRepo.count();
        var kevMaxIngest = kevRepo.findMaxIngestedAt().orElse(null);
        long nvdCount = cveRepo.count();
        var nvdLastModified = cveRepo.findMaxLastModified().orElse(null);
        return new FeedsStatusDto(
            new FeedsStatusDto.EpssStatus(epssMaxDate, epssCount),
            new FeedsStatusDto.KevStatus(kevMaxIngest, kevCount),
            new FeedsStatusDto.NvdStatus(nvdLastModified, nvdCount));
    }

    @GetMapping("/device/{id}")
    @PreAuthorize("hasAnyRole('VIEWER','ADMIN')")
    public DeviceRiskDto deviceRisk(@PathVariable long id) {
        return deviceRiskService.computeRisk(id)
            .map(DeviceRiskResult::dto)
            .orElseThrow(() -> new NoSuchElementException("Device not found: " + id));
    }

    /**
     * Batch per-device risk — {@code GET /api/risk/devices?ids=1,2,3}.
     *
     * <p>Returns a JSON object keyed by device id ({@code {"1": {...}, "2": {...}}}), one entry
     * per <em>resolvable</em> id; ids with no matching device are omitted. Each value has the
     * exact {@link DeviceRiskDto} shape of {@code GET /api/risk/device/{id}} and is produced by
     * the same cached {@link DeviceRiskService#computeRisk(long)} call, so the batch path and the
     * single path share cache entries.
     *
     * <p>The {@code ids} list is capped at {@value #BATCH_MAX_IDS}; absent or empty {@code ids}
     * yields an empty object. Eliminates the front-end N+1 (one request per row) that produced
     * the gray→green risk-badge flip on the fleet table.
     *
     * @param ids comma-separated device ids; absent/empty → {@code {}}.
     * @return    map of deviceId → {@link DeviceRiskDto} for every resolvable id (insertion order
     *            follows the requested id order, deduplicated).
     */
    @GetMapping("/devices")
    @PreAuthorize("hasAnyRole('VIEWER','ADMIN')")
    public Map<Long, DeviceRiskDto> deviceRiskBatch(@RequestParam(value = "ids", required = false) List<Long> ids) {
        Map<Long, DeviceRiskDto> out = new LinkedHashMap<>();
        if (ids == null || ids.isEmpty()) {
            return out;
        }
        int count = 0;
        for (Long id : ids) {
            if (id == null || out.containsKey(id)) continue;
            if (count >= BATCH_MAX_IDS) break;
            count++;
            deviceRiskService.computeRisk(id)
                .map(DeviceRiskResult::dto)
                .ifPresent(dto -> out.put(id, dto));
        }
        return out;
    }

    /**
     * Returns the top-N at-risk devices ordered by composite score (descending).
     *
     * <p>{@code n} is clamped to {@code [1, 100]}; default 10. The implementation walks every
     * device in the fleet and reuses the cached per-device computation from
     * {@link DeviceRiskService} (so each device's CPE→CVE match pass is shared with the single
     * and batch endpoints rather than recomputed here). The computed ranking is itself cached on
     * {@link CacheNames#TOP_RISK}, keyed by the clamped {@code n}, and evicted on the same
     * fleet-wide events (scan complete, sync complete, criticality change) that evict the
     * per-device cache.
     *
     * @param n requested page size; clamped to {@code [1, 100]}, default 10.
     * @return  list of {@link TopRiskDeviceDto}, ordered by score descending; ties broken by deviceId asc.
     */
    @GetMapping("/top")
    @PreAuthorize("hasAnyRole('VIEWER','ADMIN')")
    @Cacheable(cacheNames = CacheNames.TOP_RISK, key = "#root.target.clampTopN(#n)")
    public List<TopRiskDeviceDto> topRisk(@RequestParam(value = "n", required = false) Integer n) {
        final int clampedN = clampTopN(n);

        var devices = deviceRepo.findAll();
        if (devices.isEmpty()) return List.of();

        record Ranked(TopRiskDeviceDto dto, java.math.BigDecimal score) {}
        List<Ranked> all = new ArrayList<>(devices.size());
        for (Device d : devices) {
            // Score via the entity-keyed cache variant: shares the per-device DEVICE_RISK entry
            // with the single/batch endpoints and skips the redundant findById (we already hold
            // the entity from findAll()). The device provably exists, so the Optional is present.
            DeviceRiskResult result = deviceRiskService.computeRisk(d)
                .orElseThrow();
            DeviceRiskDto risk = result.dto();
            TopRiskDeviceDto dto = new TopRiskDeviceDto(
                d.getId(),
                d.getHostname(),
                d.getIpAddress(),
                d.getCriticality(),
                risk.score(),
                result.kevCount());
            all.add(new Ranked(dto, risk.score()));
        }
        all.sort(Comparator
            .comparing(Ranked::score, Comparator.reverseOrder())
            .thenComparing(r -> r.dto().deviceId()));
        return all.stream().limit(clampedN).map(Ranked::dto).toList();
    }

    /**
     * Clamps the requested top-N page size to {@code [1, 100]} (default {@value #TOP_DEFAULT_N}).
     * Public so the {@code @Cacheable} key SpEL on {@link #topRisk(Integer)} can key the cache by
     * the same clamped value the method body uses — keeping {@code n=null} and {@code n=10} (and
     * any over-cap request) on a single shared cache entry.
     */
    public int clampTopN(Integer n) {
        int requested = n == null ? TOP_DEFAULT_N : n;
        if (requested < 1) requested = 1;
        if (requested > TOP_MAX_N) requested = TOP_MAX_N;
        return requested;
    }
}
