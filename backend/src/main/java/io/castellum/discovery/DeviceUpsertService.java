package io.castellum.discovery;

import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.risk.Criticality;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

/**
 * Separately-injected {@code @Service} that persists a single {@link Discovery}
 * observation into the {@link Device} inventory.
 *
 * <p>The {@code @Transactional} annotation is on the public {@link #upsert(Discovery)}
 * method only. No private helpers call {@code this.upsert(...)} — the proxy self-invocation
 * hazard is structurally avoided.
 *
 * <p>Upsert logic:
 * <ul>
 *   <li>Primary key: {@code ipAddress} (UNIQUE column).</li>
 *   <li>Existing row: update {@code lastSeen}; fill {@code macAddress} and {@code hostname}
 *       only if the existing values are {@code null}.</li>
 *   <li>New row: create with {@link Criticality#MEDIUM} default.</li>
 * </ul>
 */
@Service
public class DeviceUpsertService {

    private final DeviceRepository repo;

    public DeviceUpsertService(DeviceRepository repo) {
        this.repo = repo;
    }

    @Transactional
    public Device upsert(Discovery d) {
        Optional<Device> existing = repo.findByIpAddress(d.ipAddress());
        if (existing.isPresent()) {
            Device e = existing.get();
            e.setLastSeen(d.observedAt());
            if (e.getMacAddress() == null && d.macAddress() != null) {
                e.setMacAddress(d.macAddress());
            }
            if (e.getHostname() == null && d.hostname() != null) {
                e.setHostname(d.hostname());
            }
            return repo.save(e);
        } else {
            Instant now = d.observedAt();
            Device fresh = new Device(
                null,
                d.ipAddress(),
                d.hostname(),
                d.macAddress(),
                now,
                now,
                Criticality.MEDIUM
            );
            return repo.save(fresh);
        }
    }
}
