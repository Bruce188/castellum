package io.castellum.ot;

import io.castellum.audit.AuditService;
import io.castellum.discovery.DeviceUpsertService;
import io.castellum.discovery.Discovery;
import io.castellum.discovery.DiscoverySource;
import io.castellum.domain.Device;
import io.castellum.domain.NetworkService;
import io.castellum.domain.NetworkServiceRepository;
import io.castellum.ot.bacnet.BacnetProbe;
import io.castellum.ot.dnp3.Dnp3Probe;
import io.castellum.ot.modbus.ModbusProbe;
import io.castellum.ot.s7.S7Probe;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.net.InetAddress;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

/**
 * Orchestrates OT/ICS read-only fingerprint probes for all four supported protocols.
 *
 * <p>Per probe call:
 * <ol>
 *   <li>Validates the host IP via {@link HostValidator}.</li>
 *   <li>Acquires a concurrency permit (bounded by {@code Semaphore(maxConcurrent)}).</li>
 *   <li>Dispatches the protocol-specific probe.</li>
 *   <li>On success: upserts a {@link Device} + {@link NetworkService} row.</li>
 *   <li>Always: emits an {@code OT_PROBE} audit event (success or failure) in a
 *       separate transaction (REQUIRES_NEW) so it persists even if the main
 *       transaction rolls back.</li>
 * </ol>
 */
@Service
public class OtFingerprintService {

    /** Value stored in {@code service.protocol_family} for all OT/ICS probes. */
    public static final String PROTOCOL_FAMILY_OT_ICS = "OT_ICS";

    private final DeviceUpsertService deviceUpsertService;
    private final NetworkServiceRepository networkServiceRepository;
    private final AuditService auditService;
    private final Semaphore concurrencyLimiter;

    private final ModbusProbe modbusProbe;
    private final Dnp3Probe dnp3Probe;
    private final S7Probe s7Probe;
    private final BacnetProbe bacnetProbe;

    public OtFingerprintService(
            DeviceUpsertService deviceUpsertService,
            NetworkServiceRepository networkServiceRepository,
            AuditService auditService,
            @Value("${castellum.ot.probe.connect-timeout-ms:3000}") int connectTimeoutMs,
            @Value("${castellum.ot.probe.read-timeout-ms:5000}") int readTimeoutMs,
            @Value("${castellum.ot.probe.max-concurrent:8}") int maxConcurrent) {
        this.deviceUpsertService = deviceUpsertService;
        this.networkServiceRepository = networkServiceRepository;
        this.auditService = auditService;
        this.concurrencyLimiter = new Semaphore(maxConcurrent);
        this.modbusProbe = new ModbusProbe(connectTimeoutMs, readTimeoutMs);
        this.dnp3Probe = new Dnp3Probe(connectTimeoutMs, readTimeoutMs);
        this.s7Probe = new S7Probe(connectTimeoutMs, readTimeoutMs);
        this.bacnetProbe = new BacnetProbe(readTimeoutMs);
    }

    /**
     * Result of a successful OT fingerprint probe.
     *
     * @param deviceId   ID of the device row
     * @param serviceId  ID of the network-service row
     * @param protocol   protocol that was probed
     * @param host       target IPv4 string
     * @param port       target port
     * @param vendor     decoded vendor name
     * @param product    decoded product/model name
     * @param version    decoded firmware/software version
     * @param rawFields  all decoded protocol-native fields
     * @param observedAt timestamp of the successful probe
     */
    public record OtProbeResult(
        long deviceId,
        long serviceId,
        OtProtocol protocol,
        String host,
        int port,
        String vendor,
        String product,
        String version,
        Map<String, String> rawFields,
        Instant observedAt
    ) {}

    /**
     * Probes host:port for the given protocol, persists a {@link NetworkService} row on success,
     * and always emits an {@code OT_PROBE} audit event.
     *
     * @param host     IPv4 address string (validated via {@link HostValidator})
     * @param port     TCP/UDP port
     * @param protocol OT protocol to use
     * @return probe result on success
     * @throws IllegalArgumentException        if {@code host} is not a valid IPv4 address
     * @throws OtProbeUnreachableException     if the target is unreachable
     * @throws OtProbeTimeoutException         if the probe times out
     * @throws OtProbeDecodeException          if the response fails to decode
     * @throws OtProbeNotImplementedException  if the protocol is not yet wired
     */
    @Transactional
    public OtProbeResult probe(String host, int port, OtProtocol protocol) {
        InetAddress addr = HostValidator.requireValid(host);

        long startMs = System.currentTimeMillis();
        boolean acquired = false;
        try {
            acquired = concurrencyLimiter.tryAcquire(2, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new OtProbeTimeoutException("interrupted waiting for concurrency permit");
        }
        if (!acquired) {
            throw new OtProbeTimeoutException("concurrency limit exceeded: too many concurrent OT probes");
        }

        try {
            return doProbe(host, port, protocol, addr, startMs);
        } catch (OtProbeException ex) {
            emitAuditFailure(host, port, protocol, ex, startMs);
            throw ex;
        } finally {
            concurrencyLimiter.release();
        }
    }

    // ---- Private implementation ----

    private OtProbeResult doProbe(String host, int port, OtProtocol protocol, InetAddress addr, long startMs) {
        Map<String, String> rawFields;
        String vendor = null;
        String product = null;
        String version = null;

        switch (protocol) {
            case MODBUS_TCP -> {
                Map<Integer, String> objs = modbusProbe.fingerprint(addr, port);
                rawFields = toStringMap(objs);
                vendor = objs.get(0);
                // Object 1 = ProductCode, object 5 = ProductName (preferred for product)
                product = objs.getOrDefault(5, objs.get(1));
                version = objs.get(2);
            }
            case DNP3 -> {
                Map<String, String> attrs = dnp3Probe.fingerprint(addr, port);
                rawFields = attrs;
                vendor = attrs.get("vendor-name");
                product = attrs.get("device-name");
                version = attrs.get("attr-0-247"); // firmware version attribute
            }
            case S7COMM -> {
                Map<String, String> szlFields = s7Probe.fingerprint(addr, port);
                rawFields = szlFields;
                vendor = szlFields.getOrDefault("manufacturer", "Siemens");
                product = szlFields.get("ordering-number");
                version = szlFields.get("firmware-version");
            }
            case BACNET_IP -> {
                Map<String, String> bacFields = bacnetProbe.fingerprint(addr, port);
                rawFields = bacFields;
                vendor = bacFields.get("vendor-name");
                product = bacFields.get("model-name");
            }
            default -> throw new OtProbeNotImplementedException("Protocol not yet implemented: " + protocol);
        }

        Instant now = Instant.now();
        long durationMs = System.currentTimeMillis() - startMs;

        // Upsert Device
        Device device = deviceUpsertService.upsert(
            new Discovery(host, null, null, DiscoverySource.OT_PROBE, now, null, false));

        // Upsert NetworkService
        NetworkService svc = networkServiceRepository
            .findByDeviceIdAndPortAndProtocol(device.getId(), port, protocol.l7Name())
            .orElseGet(NetworkService::new);
        svc.setDeviceId(device.getId());
        svc.setPort(port);
        svc.setProtocol(protocol.l7Name());
        svc.setName(protocol.l7Name());
        svc.setVersion(version);
        svc.setVendor(vendor);
        svc.setProduct(product);
        svc.setProtocolFamily(PROTOCOL_FAMILY_OT_ICS);
        svc.setObservedAt(now);
        svc = networkServiceRepository.save(svc);

        // Audit: success
        Map<String, Object> auditPayload = new LinkedHashMap<>();
        auditPayload.put("host", host);
        auditPayload.put("port", port);
        auditPayload.put("protocol", protocol.name());
        auditPayload.put("outcome", "success");
        auditPayload.put("vendor", vendor);
        auditPayload.put("product", product);
        auditPayload.put("version", version);
        auditPayload.put("durationMs", durationMs);
        auditService.recordEvent("system", "OT_PROBE", "ot_probe",
            host + ":" + port + "/" + protocol.name(), auditPayload);

        return new OtProbeResult(
            device.getId(), svc.getId(), protocol,
            host, port, vendor, product, version, rawFields, now);
    }

    /**
     * Emits a failure audit event. Uses REQUIRES_NEW propagation so the audit row
     * persists even when the calling transaction rolls back (no service row on failure).
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    protected void emitAuditFailure(String host, int port, OtProtocol protocol,
                                    OtProbeException ex, long startMs) {
        long durationMs = System.currentTimeMillis() - startMs;
        String errorMessage = ex.getMessage();
        if (errorMessage != null && errorMessage.length() > 256) {
            errorMessage = errorMessage.substring(0, 256);
        }
        Map<String, Object> auditPayload = new LinkedHashMap<>();
        auditPayload.put("host", host);
        auditPayload.put("port", port);
        auditPayload.put("protocol", protocol.name());
        auditPayload.put("outcome", "failure");
        auditPayload.put("errorClass", ex.getClass().getSimpleName());
        auditPayload.put("errorMessage", errorMessage);
        auditPayload.put("durationMs", durationMs);
        auditService.recordEvent("system", "OT_PROBE", "ot_probe",
            host + ":" + port + "/" + protocol.name(), auditPayload);
    }

    private static Map<String, String> toStringMap(Map<Integer, String> intMap) {
        Map<String, String> result = new LinkedHashMap<>();
        intMap.forEach((k, v) -> result.put(String.valueOf(k), v));
        return result;
    }
}
